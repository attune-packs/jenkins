# Source Verification

- Upstream: https://github.com/StackStorm-Exchange/stackstorm-jenkins
- Upstream version: `1.0.1`
- Verified tag: `v1.0.1`
- Verified revision: `884692248ce19ae3220e88b5f4f5d446394e683a`
- Revision date: `2024-01-16T01:06:26Z`
- Revision signature: GitHub reports `valid`; a local Git check cannot verify the GitHub web-flow key
- Upstream license: Apache License 2.0
- Upstream NOTICE: none at the verified revision
- API baseline reviewed: Jenkins weekly `2.577`, released 2026-08-11
- Jenkins core revision: `82c37634b354dd2832ae80772ef2548cc388671f`
- Pipeline `workflow-job-plugin` revision: `0062354a9bb98b716ecef7584a446d85b7fe4e04`
- Review date: 2026-08-15

Authoritative references:

- https://www.jenkins.io/doc/book/using/remote-access-api/
- https://www.jenkins.io/doc/book/security/csrf-protection/
- https://www.jenkins.io/doc/book/system-administration/authenticating-scripted-clients/
- https://www.jenkins.io/doc/book/using/aborting-a-build/
- https://github.com/jenkinsci/jenkins/tree/jenkins-2.577/core/src/main/java
- https://github.com/jenkinsci/workflow-job-plugin/blob/0062354a9bb98b716ecef7584a446d85b7fe4e04/src/main/java/org/jenkinsci/plugins/workflow/job/WorkflowRun.java

The current documentation and source establish the behavior used by this pack:

- Remote API objects are exposed below object-specific `api/json` routes.
- Builds use POST to `build` or `buildWithParameters`; successful scheduling
  identifies a queue item through the response `Location` header.
- API-token-authenticated POST requests are crumb-exempt. Password/basic POST
  requests require a crumb and the session cookie created while fetching it
  when CSRF protection is active.
- `X-Jenkins` identifies a Jenkins response and reports controller version.
- Queue cancellation is POST `queue/cancelItem?id=...`. Queue left-item records
  are forgetful and currently expire after five minutes.
- Pipeline `stop`, `term`, and `kill` are distinct and increasingly forceful.
- Progressive logs use `logText/progressiveText`, `start`, `X-Text-Size`, and
  `X-More-Data`.
- `Computer.changeOfflineCause` marks a node temporarily offline without
  toggling. Jenkins exposes online transition through `toggleOffline`, which
  can invert the wrong state if another actor changes it between read and POST.

The StackStorm pack provided 16 actions around `python-jenkins`. This adaptation
uses one direct, bounded HTTP client and 25 curated actions. It omits upstream
plugin installation, rebuild-last, regex filtering, log retention mutation,
configuration overrides, and webhook examples. It adds job lifecycle, explicit
queue/build identity, artifacts, progressive logs, nodes, plugin reads, TLS,
crumbs, and confirmation controls.
