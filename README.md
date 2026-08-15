# Jenkins Attune Pack

This pack adapts the Apache-2.0 StackStorm Exchange Jenkins pack at revision
`884692248ce19ae3220e88b5f4f5d446394e683a` into 25 flat JSON actions over the
current Jenkins Remote Access API. The reviewed baseline is Jenkins weekly
2.577 and Pipeline `workflow-job-plugin` revision
`0062354a9bb98b716ecef7584a446d85b7fe4e04`. See [SOURCE.md](SOURCE.md).

## Requirements

- Python 3.10 or newer on the Attune worker.
- `requests`, installed from `requirements.txt`.
- Network access from that worker to the fixed Jenkins HTTPS origin.
- An encrypted, pack-owned Attune Key, normally `jenkins.credentials`.
- Jenkins permissions appropriate to each selected operation.
- An existing worker-local `ATTUNE_ARTIFACTS_DIR` for downloads.

## Credentials And TLS

Actions accept only `credential_key`; URLs and authentication secrets cannot be
supplied as action parameters. API-token credential Key:

```json
{
  "base_url": "https://ci.example.com/jenkins",
  "username": "attune-robot",
  "api_token": "REDACTED",
  "verify_tls": true,
  "ca_cert": "-----BEGIN CERTIFICATE-----\nREDACTED_CA\n-----END CERTIFICATE-----",
  "build_tokens": {
    "deploy-production": "REDACTED_REMOTE_BUILD_TOKEN"
  }
}
```

For legacy password/basic authentication, replace `api_token` with `password`.
Anonymous access is represented by omitting all three authentication fields.
`api_token` and `password` are mutually exclusive. `build_tokens` is optional;
`build_trigger.build_token_name` selects a value without exposing it in action
input or output.

The client requires HTTPS and certificate verification. `verify_tls` defaults
to and must remain `true`. `ca_cert` supplies a private CA bundle through a
mode-0600 temporary file that is removed after the request. The base URL may
include a simple Jenkins context path, but credentials, queries, fragments,
percent-encoding, dot segments, repeated separators, and redirects are rejected.
Because the origin comes only from a pack-owned Key and endpoint paths are built
internally, action callers cannot redirect requests to an arbitrary SSRF target.
The Key and worker network policy remain the administrative trust boundary.

API-token POSTs are crumb-exempt in current Jenkins. Password/basic mutations
first fetch `/crumbIssuer/api/json` and reuse that exact HTTP session so its
cookie and dynamic crumb header remain paired. A `404` means the issuer is
disabled. Crumb or mutation failures are never retried.

## Actions

| Action | Purpose |
|---|---|
| `jenkins.server_info` | Verify `X-Jenkins` and return bounded controller fields |
| `jenkins.jobs_list` | Flatten jobs/folders to a bounded depth of 0 through 10 |
| `jenkins.job_get` | Read one folder-qualified job |
| `jenkins.job_create` | Create one job from validated XML |
| `jenkins.job_update` | Replace one job configuration with validated XML |
| `jenkins.job_delete` | Delete one confirmed job |
| `jenkins.job_enable` | Enable a job type supporting the endpoint |
| `jenkins.job_disable` | Disable a job type supporting the endpoint |
| `jenkins.build_trigger` | Trigger once with scalar parameters and/or a named remote token; optionally wait for start |
| `jenkins.queue_list` | List visible queue items |
| `jenkins.queue_get` | Read one exact queue ID and normalized state |
| `jenkins.queue_wait` | Wait for that queue ID to start/cancel or time out |
| `jenkins.queue_cancel` | Verify queue ID and job, then cancel only the queued item |
| `jenkins.build_get` | Read one exact build number |
| `jenkins.build_wait` | Wait for that build to complete or time out |
| `jenkins.build_stop` | Request the normal build/Pipeline abort path |
| `jenkins.build_term` | Force running Pipeline steps to terminate |
| `jenkins.build_kill` | Hard-kill a Pipeline as the last resort |
| `jenkins.console_log` | Read a bounded progressive log chunk and next offset |
| `jenkins.artifact_list` | List exact artifact relative paths |
| `jenkins.artifact_download` | Download one listed artifact beneath `ATTUNE_ARTIFACTS_DIR` |
| `jenkins.nodes_list` | List bounded computer status fields |
| `jenkins.node_get` | Read one computer |
| `jenkins.node_offline` | Mark a computer temporarily offline without toggling |
| `jenkins.plugins_list` | List installed plugin state and versions |

All actions receive one flat JSON object and return:

```json
{
  "operation": "queue_get",
  "data": {"state": "started", "queue_id": 42, "item": {}},
  "meta": {
    "jenkins_version": "2.577",
    "authentication": "api_token",
    "crumb_used": false,
    "http_status": 200
  }
}
```

## Safety Contracts

Folder and job names are split only at caller-supplied `/` boundaries and each
segment is percent-encoded. Empty, `.`, `..`, absolute, and backslash paths are
rejected. Queue IDs and positive build numbers are never interpreted as job
paths or permalinks.

`build_trigger` performs exactly one POST. It obtains the queue ID only from a
same-origin, same-context `Location` header. If Jenkins accepts the mutation but
does not provide a safe queue location, the result is
`accepted_identity_unknown` with `retry_safe: false`. Polling never guesses from
`nextBuildNumber`, `lastBuild`, or a job queue search. If Jenkins forgets the
queue item before its executable is observed, the action fails with unknown
identity rather than selecting a potentially unrelated build.

Waits are bounded to 3,600 seconds, intervals to 1 through 30 seconds, and each
HTTP request to 1 through 120 seconds. A normal wait timeout returns structured
`timed_out` state. JSON is limited to 8 MiB, job XML to 1 MiB, each progressive
log chunk to 2 MiB, and artifact downloads to 256 MiB or a lower caller limit.
No mutation is retried.

Exact confirmations are:

| Operation | Confirmation |
|---|---|
| Create job | `create job <job_path>` |
| Replace config | `replace config <job_path>` |
| Delete job | `delete job <job_path>` |
| Cancel queue item | `cancel queue <id> for <job_path>` |
| Stop build | `stop build <job_path>#<number>` |
| Terminate Pipeline | `term build <job_path>#<number>` |
| Kill Pipeline | `kill build <job_path>#<number>` |
| Mark node offline | `offline node <node_name>` |

Queue cancellation reads the queue item first, verifies its job, and refuses if
an executable is already assigned. It never converts cancellation into build
termination. Build termination reads the exact build first and refuses if it is
not currently running. `stop` is the normal interrupt/abort request. `term`
forces Pipeline leaf steps to fail and should follow an ineffective `stop`.
`kill` discards Pipeline execution state and is a last resort. Jenkins accepts
`term` and `kill` only for compatible Pipeline builds.

Job XML is privileged code/configuration, not ordinary data. The create and
replace actions require exact confirmation, enforce UTF-8 and size limits,
parse well-formed XML, constrain the root name, and reject DTD, entity,
stylesheet, namespace-root, and XInclude constructs. The pack never returns
`config.xml` and does not attempt to determine whether plugin-specific XML is
semantically safe. Grant Job/Create and Job/Configure narrowly.

Artifact download first requires an exact path returned by the build artifact
list. Both remote artifact and local destination paths reject traversal. The
destination root must be an existing absolute non-symlink directory; symlinked
parents and non-file targets are rejected. Data is written to a mode-0600
temporary file, size-checked while streaming, fsynced, and atomically replaced.
Protect the worker filesystem because a malicious process with concurrent write
access to the artifact root can still race filesystem checks.

Server response bodies and transport exception messages are never included in
errors. Credentials and remote build tokens are never output or logged. Jenkins
data returned by successful read actions can itself contain sensitive job,
parameter, queue, plugin, or node information and must be protected by Attune
execution and result permissions.

## Intentional Gaps

Jenkins 2.577 exposes a safe, non-toggling `changeOfflineCause` POST for marking
a node offline, so `node_offline` uses it and verifies the resulting state.
Bringing a node online is exposed through `toggleOffline`; a concurrent state
change can make that endpoint take an already-online node offline. This pack
therefore has no `node_online` action. Use a separately controlled Jenkins CLI
workflow if an explicit online transition is required.

Live integration is not run by the unit suite. Job types and plugins vary in
their support for enable/disable, configuration XML, parameters, artifacts,
Pipeline termination, node permissions, and proxy/header behavior. Validate
those surfaces against the target controller in a non-production folder before
granting production permissions.

## Validation

```bash
python3 -m unittest discover -s tests -v
attune --output json pack check /home/david/Codebase/attune-packs/jenkins
attune pack test /home/david/Codebase/attune-packs/jenkins --detailed
```

The deterministic tests mock all Jenkins and Attune Key calls and require no
live controller or undeclared Jenkins library.

## License

The verified upstream Apache License 2.0 text is included in [LICENSE](LICENSE).
Attribution and material changes are recorded in [NOTICE](NOTICE).
