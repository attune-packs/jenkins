from __future__ import annotations

import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import types
import unittest
from unittest import mock

try:
    import requests
except ModuleNotFoundError:
    requests = types.ModuleType("requests")

    class RequestException(Exception):
        pass

    class ConnectionError(RequestException):
        pass

    class Session:
        def __init__(self):
            self.auth = None

        def request(self, *args, **kwargs):
            raise ConnectionError("network unavailable in unit tests")

        def close(self):
            pass

    requests.RequestException = RequestException
    requests.ConnectionError = ConnectionError
    requests.Response = object
    requests.Session = Session
    sys.modules["requests"] = requests


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import jenkins_client as client  # noqa: E402


class Response:
    def __init__(self, value=None, status_code=200, headers=None, body=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.body = json.dumps(value).encode() if body is None and value is not None else (body or b"")
        self.closed = False

    def iter_content(self, chunk_size=65536):
        del chunk_size
        if self.body:
            yield self.body

    def close(self):
        self.closed = True


def jenkins(**overrides):
    credential = {
        "base_url": "https://ci.example.invalid/jenkins",
        "username": "robot",
        "api_token": "TOP-SECRET",
        "verify_tls": True,
    }
    credential.update(overrides)
    return client.JenkinsClient(credential, 10)


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {
            path.stem: path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "actions").glob("*.yaml"))
        }

    def test_curated_action_inventory(self):
        self.assertEqual(
            {
                "artifact_download", "artifact_list", "build_get", "build_kill", "build_stop",
                "build_term", "build_trigger", "build_wait", "console_log", "job_create",
                "job_delete", "job_disable", "job_enable", "job_get", "job_update", "jobs_list",
                "node_get", "node_offline", "nodes_list", "plugins_list", "queue_cancel",
                "queue_get", "queue_list", "queue_wait", "server_info",
            },
            set(self.actions),
        )

    def test_actions_are_flat_stdin_json_without_inline_credentials(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                expected = {
                    "ref": f"jenkins.{name}", "runner_type": "python", "runtime_version": '\">=3.10\"',
                    "entry_point": "jenkins_action.py", "parameter_delivery": "stdin",
                    "parameter_format": "json", "output_format": "json",
                }
                for field, value in expected.items():
                    self.assertRegex(text, rf"(?m)^{field}: {re.escape(value)}$")
                self.assertIn("default_execution_permission_set_refs: [standard]", text)
                self.assertRegex(text, r"credential_key: \{[^\n]*default: jenkins\.credentials[^\n]*\}")
                for field in ("operation", "data", "meta"):
                    self.assertRegex(text, rf"(?m)^  {field}: \{{type:")
                self.assertNotRegex(text, r"(?m)^  (?:api_token|password|base_url|build_token):")

    def test_source_license_and_online_gap_are_documented(self):
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        revision = "884692248ce19ae3220e88b5f4f5d446394e683a"
        self.assertIn(f'source_revision: "{revision}"', pack)
        self.assertIn('source_version: "1.0.1"', pack)
        self.assertIn('license: "Apache-2.0"', pack)
        self.assertIn(revision, (ROOT / "NOTICE").read_text(encoding="utf-8"))
        self.assertIn("Apache License", (ROOT / "LICENSE").read_text(encoding="utf-8"))
        self.assertIn("toggleOffline", (ROOT / "README.md").read_text(encoding="utf-8"))


class ValidationTests(unittest.TestCase):
    def test_base_url_is_https_fixed_origin_with_unambiguous_context(self):
        bad = [
            "http://ci.invalid", "https://user:secret@ci.invalid", "file:///tmp/jenkins",
            "https://ci.invalid/jenkins%2Fadmin", "https://ci.invalid/a/../b",
            "https://ci.invalid/a//b", "https://ci.invalid/jenkins?target=x",
            "https://bad_host.invalid/jenkins", "https://ci.invalid./jenkins",
        ]
        for base_url in bad:
            with self.subTest(base_url=base_url), self.assertRaises(client.JenkinsPackError):
                client.JenkinsClient({"base_url": base_url}, 10)
        with self.assertRaisesRegex(client.JenkinsPackError, "must be true"):
            client.JenkinsClient({"base_url": "https://ci.invalid", "verify_tls": False}, 10)

    def test_credentials_are_mutually_complete_and_build_tokens_are_validated(self):
        for credential in (
            {"base_url": "https://ci.invalid", "username": "robot"},
            {"base_url": "https://ci.invalid", "api_token": "x"},
            {"base_url": "https://ci.invalid", "username": "r", "api_token": "x", "password": "y"},
            {"base_url": "https://ci.invalid", "username": "bad:user", "api_token": "x"},
            {"base_url": "https://ci.invalid", "build_tokens": {"deploy": "bad\nvalue"}},
        ):
            with self.subTest(credential=credential), self.assertRaises(client.JenkinsPackError):
                client.JenkinsClient(credential, 10)

    def test_folder_job_and_artifact_paths_encode_segments_and_reject_confusion(self):
        route, name = client._job_route("team one/release+#1")
        self.assertEqual("team one/release+#1", name)
        self.assertEqual("/job/team%20one/job/release%2B%231", route)
        for value in ("/absolute", "folder//job", "folder/../job", "folder\\job", "folder/./job"):
            with self.subTest(value=value), self.assertRaises(client.JenkinsPackError):
                client._job_route(value)

    def test_xml_is_bounded_well_formed_and_rejects_external_or_internal_entities(self):
        valid = client._xml_config({"config_xml": "<flow-definition><description>x</description></flow-definition>"})
        self.assertTrue(valid.startswith(b"<flow-definition>"))
        bad = [
            "<!DOCTYPE project [<!ENTITY x 'secret'>]><project>&x;</project>",
            "<project><xi:include href='file:///etc/passwd'/></project>",
            "<project xmlns:x='http://www.w3.org/2001/XInclude'><x:include href='file:///etc/passwd'/></project>",
            "<project>",
            "<ns:project xmlns:ns='urn:test'/>",
        ]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(client.JenkinsPackError):
                client._xml_config({"config_xml": value})
        with self.assertRaisesRegex(client.JenkinsPackError, "1 MiB"):
            client._xml_config({"config_xml": "<project>" + "x" * client.MAX_XML_BYTES + "</project>"})

    def test_location_requires_same_origin_context_and_exact_queue_shape(self):
        api = jenkins()
        self.assertEqual(42, api.queue_id_from_location("https://ci.example.invalid/jenkins/queue/item/42/"))
        self.assertEqual(43, api.queue_id_from_location("/jenkins/queue/item/43/"))
        for location in (
            "https://evil.invalid/jenkins/queue/item/42/", "/queue/item/42/",
            "/jenkins/job/demo/42/", "/jenkins/queue/item/42/?token=secret",
        ):
            self.assertIsNone(api.queue_id_from_location(location))


class ClientTests(unittest.TestCase):
    def test_api_token_post_is_single_request_without_crumb_or_redirect(self):
        api = jenkins()
        response = Response(status_code=302, headers={"Location": "/jenkins/job/demo/"})
        with mock.patch.object(api.session, "request", return_value=response) as request:
            result = api.post_empty("/job/demo/disable")
        self.assertEqual(302, result["http_status"])
        self.assertEqual(1, request.call_count)
        self.assertFalse(request.call_args.kwargs["allow_redirects"])
        self.assertNotIn("Jenkins-Crumb", request.call_args.kwargs["headers"])

    def test_password_post_fetches_crumb_in_same_session(self):
        api = jenkins(api_token=None, password="PASSWORD-SECRET")
        responses = [
            Response({"crumbRequestField": "Jenkins-Crumb", "crumb": "crumb-value"}, headers={"X-Jenkins": "2.577"}),
            Response(status_code=204),
        ]
        with mock.patch.object(api.session, "request", side_effect=responses) as request:
            api.post_empty("/job/demo/disable")
        self.assertEqual(2, request.call_count)
        self.assertEqual("GET", request.call_args_list[0].args[0])
        self.assertEqual("crumb-value", request.call_args_list[1].kwargs["headers"]["Jenkins-Crumb"])
        self.assertTrue(api.crumb_used)

    def test_disabled_crumb_issuer_allows_password_post_without_retry(self):
        api = jenkins(api_token=None, password="PASSWORD-SECRET")
        with mock.patch.object(api.session, "request", side_effect=[Response(status_code=404), Response(status_code=204)]) as request:
            api.post_empty("/job/demo/disable")
        self.assertEqual(2, request.call_count)
        self.assertFalse(api.crumb_used)

    def test_http_and_transport_errors_never_expose_body_or_library_message(self):
        api = jenkins()
        with mock.patch.object(api.session, "request", return_value=Response({"secret": "TOP-SECRET"}, status_code=403)):
            with self.assertRaises(client.JenkinsPackError) as caught:
                api.get_json("/api/json")
        self.assertNotIn("TOP-SECRET", str(caught.exception))
        with mock.patch.object(api.session, "request", side_effect=requests.ConnectionError("TOP-SECRET URL")):
            with self.assertRaises(client.JenkinsPackError) as caught:
                api.get_json("/api/json")
        self.assertNotIn("TOP-SECRET", str(caught.exception))

    def test_server_info_requires_jenkins_identity_header(self):
        api = jenkins()
        with mock.patch.object(api.session, "request", return_value=Response({"mode": "NORMAL"})):
            with self.assertRaisesRegex(client.JenkinsPackError, "X-Jenkins"):
                client._execute(api, "server_info", {})
        with mock.patch.object(api.session, "request", return_value=Response({"mode": "NORMAL"}, headers={"X-Jenkins": "2.577"})):
            self.assertEqual("NORMAL", client._execute(api, "server_info", {})["mode"])

    def test_trigger_uses_exact_location_and_never_retries_mutation(self):
        api = jenkins(build_tokens={"deploy": "BUILD-SECRET"})
        responses = [
            Response({"fullName": "team/release"}),
            Response(status_code=201, headers={"Location": "https://ci.example.invalid/jenkins/queue/item/77/"}),
        ]
        with mock.patch.object(api.session, "request", side_effect=responses) as request:
            result = client._execute(api, "build_trigger", {
                "job_path": "team/release", "parameters": {"VERSION": "1.2", "DRY_RUN": False},
                "build_token_name": "deploy",
            })
        self.assertEqual(77, result["queue_id"])
        self.assertEqual(2, request.call_count)
        mutation = request.call_args_list[1]
        self.assertEqual("https://ci.example.invalid/jenkins/job/team/job/release/buildWithParameters", mutation.args[1])
        self.assertEqual("BUILD-SECRET", mutation.kwargs["params"]["token"])
        self.assertEqual("false", mutation.kwargs["data"]["DRY_RUN"])

    def test_trigger_without_safe_location_reports_uncertain_success_not_retryable(self):
        api = jenkins()
        with mock.patch.object(api.session, "request", side_effect=[Response({"fullName": "demo"}), Response(status_code=201)]) as request:
            result = client._execute(api, "build_trigger", {"job_path": "demo"})
        self.assertEqual("accepted_identity_unknown", result["state"])
        self.assertFalse(result["retry_safe"])
        self.assertEqual(2, request.call_count)

    def test_queue_wait_never_guesses_when_record_disappears_and_timeout_is_bounded(self):
        api = jenkins()
        with mock.patch.object(api, "get_json", return_value=None):
            with self.assertRaisesRegex(client.JenkinsPackError, "was not guessed"):
                client._wait_queue(api, 12, 30, 3)
        queued = {"id": 12, "task": {"name": "demo"}}
        with mock.patch.object(api, "get_json", return_value=queued), mock.patch.object(client.time, "monotonic", side_effect=[0.0, 1.0]):
            result = client._wait_queue(api, 12, 1, 3)
        self.assertEqual("timed_out", result["state"])

    def test_queue_cancel_validates_job_and_refuses_to_stop_started_build(self):
        api = jenkins()
        wrong = {"id": 9, "task": {"fullName": "other"}}
        with mock.patch.object(api, "get_json", return_value=wrong):
            with self.assertRaisesRegex(client.JenkinsPackError, "confirmed job_path"):
                client._execute(api, "queue_cancel", {"queue_id": 9, "job_path": "demo", "confirmation": "cancel queue 9 for demo"})
        started = {"id": 9, "task": {"fullName": "demo"}, "executable": {"number": 44}}
        with mock.patch.object(api, "get_json", return_value=started), mock.patch.object(api, "post") as post:
            with self.assertRaisesRegex(client.JenkinsPackError, "no build was stopped"):
                client._execute(api, "queue_cancel", {"queue_id": 9, "job_path": "demo", "confirmation": "cancel queue 9 for demo"})
        post.assert_not_called()

    def test_queue_task_folder_identity_can_use_same_origin_job_url(self):
        api = jenkins()
        item = {"id": 9, "task": {"name": "release", "url": "https://ci.example.invalid/jenkins/job/team/job/release/"}}
        self.assertTrue(client._queue_task_matches(api, item, "team/release"))
        item["task"]["url"] = "https://evil.invalid/jenkins/job/team/job/release/"
        self.assertFalse(client._queue_task_matches(api, item, "team/release"))

    def test_build_termination_targets_confirmed_number_and_distinct_endpoint(self):
        for operation, verb in (("build_stop", "stop"), ("build_term", "term"), ("build_kill", "kill")):
            api = jenkins()
            with self.subTest(operation=operation), mock.patch.object(api, "get_json", return_value={"number": 44, "building": True}), mock.patch.object(api, "post_empty", return_value={"changed": True, "http_status": 302}) as post:
                result = client._execute(api, operation, {"job_path": "team/demo", "build_number": 44, "confirmation": f"{verb} build team/demo#44"})
                post.assert_called_once_with(f"/job/team/job/demo/44/{verb}")
                self.assertEqual(verb, result["termination"])

    def test_completed_build_is_never_terminated(self):
        api = jenkins()
        with mock.patch.object(api, "get_json", return_value={"number": 44, "building": False}), mock.patch.object(api, "post_empty") as post:
            with self.assertRaisesRegex(client.JenkinsPackError, "not running"):
                client._execute(api, "build_stop", {"job_path": "demo", "build_number": 44, "confirmation": "stop build demo#44"})
        post.assert_not_called()

    def test_mismatched_build_number_is_rejected_before_mutation(self):
        api = jenkins()
        with mock.patch.object(api, "get_json", return_value={"number": 45, "building": True}), mock.patch.object(api, "post_empty") as post:
            with self.assertRaisesRegex(client.JenkinsPackError, "build identity"):
                client._execute(api, "build_stop", {"job_path": "demo", "build_number": 44, "confirmation": "stop build demo#44"})
        post.assert_not_called()

    def test_progressive_log_uses_offset_headers_and_size_limit(self):
        api = jenkins()
        response = Response(status_code=200, body=b"hello\n", headers={"X-Text-Size": "6", "X-More-Data": "true"})
        with mock.patch.object(api.session, "request", return_value=response):
            result = client._execute(api, "console_log", {"job_path": "demo", "build_number": 4, "start": 0, "max_bytes": 64})
        self.assertEqual("hello\n", result["text"])
        self.assertEqual(6, result["next_start"])
        self.assertTrue(result["more"])
        too_large = Response(status_code=200, body=b"12345", headers={"X-Text-Size": "5"})
        with mock.patch.object(api.session, "request", return_value=too_large), self.assertRaisesRegex(client.JenkinsPackError, "size limit"):
            client._execute(api, "console_log", {"job_path": "demo", "build_number": 4, "max_bytes": 4})

    def test_artifact_download_is_list_bound_size_bounded_and_confined(self):
        api = jenkins()
        list_response = Response({"artifacts": [{"fileName": "app.tgz", "relativePath": "dist/app.tgz"}]})
        artifact_response = Response(status_code=200, body=b"payload", headers={"Content-Length": "7"})
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}), mock.patch.object(api.session, "request", side_effect=[list_response, artifact_response]):
            result = client._execute(api, "artifact_download", {
                "job_path": "demo", "build_number": 4, "artifact_path": "dist/app.tgz",
                "destination": "releases/app.tgz", "max_bytes": 8,
            })
            self.assertEqual(b"payload", Path(result["destination"]).read_bytes())
            self.assertEqual(hashlib_sha256(b"payload"), result["sha256"])
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}):
            for destination in ("../escape", "/absolute", "safe/../../escape"):
                with self.subTest(destination=destination), self.assertRaises(client.JenkinsPackError):
                    client._destination(destination)

    def test_artifact_parent_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            Path(root, "link").symlink_to(outside, target_is_directory=True)
            with mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": root}), self.assertRaisesRegex(client.JenkinsPackError, "safe directory"):
                client._destination("link/file.bin")

    def test_node_offline_uses_non_toggling_endpoint_and_exact_confirmation(self):
        api = jenkins()
        with mock.patch.object(api, "get_json", side_effect=[{"temporarilyOffline": False}, {"temporarilyOffline": True}]), mock.patch.object(api, "post_empty", return_value={"changed": True}) as post:
            result = client._execute(api, "node_offline", {"node_name": "linux one", "message": "maintenance", "confirmation": "offline node linux one"})
        post.assert_called_once_with("/computer/linux%20one/changeOfflineCause", params={"offlineMessage": "maintenance"})
        self.assertTrue(result["temporarily_offline"])


def hashlib_sha256(value: bytes) -> str:
    import hashlib
    return hashlib.sha256(value).hexdigest()


class EntryPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib.util

        spec = importlib.util.spec_from_file_location("jenkins_action_test", ROOT / "actions" / "jenkins_action.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_invalid_input_and_unknown_errors_do_not_echo_secrets(self):
        for raw, error in (("[]", None), ('{"config_xml":"DO-NOT-ECHO"}', RuntimeError("DO-NOT-ECHO"))):
            stdout, stderr = io.StringIO(), io.StringIO()
            patch_execute = mock.patch.object(self.module, "execute_action", side_effect=error) if error else mock.patch.object(self.module, "execute_action")
            with patch_execute, mock.patch.dict(os.environ, {"ATTUNE_ACTION": "jenkins.job_update"}), mock.patch("sys.stdin", io.StringIO(raw)), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                self.assertEqual(1, self.module.main())
            self.assertEqual("", stdout.getvalue())
            self.assertNotIn("DO-NOT-ECHO", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
