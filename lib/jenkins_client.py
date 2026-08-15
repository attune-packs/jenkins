"""Bounded Jenkins Remote Access API client and action dispatcher."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote, urlsplit

import requests


DEFAULT_CREDENTIAL_KEY = "jenkins.credentials"
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_XML_BYTES = 1024 * 1024
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_XML_DANGEROUS = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)|<\s*xi:include\b|<\?xml-stylesheet\b", re.I)


class JenkinsPackError(Exception):
    """An action-safe error without credentials or server response bodies."""


def _fetch_key(key_ref: str) -> dict[str, Any]:
    if not isinstance(key_ref, str) or not key_ref.strip():
        raise JenkinsPackError("credential_key must be a non-empty string")
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(client=attune.context.client, key_ref=key_ref)
    except Exception as exc:
        raise JenkinsPackError(f"could not read Jenkins credential Key ({type(exc).__name__})") from None
    if response.status_code != 200 or response.parsed is None:
        if response.status_code == 404:
            raise JenkinsPackError("Jenkins credential Key was not found")
        raise JenkinsPackError(f"could not read Jenkins credential Key (HTTP {response.status_code})")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise JenkinsPackError("Jenkins credential Key must contain a JSON object") from None
    if not isinstance(value, dict):
        raise JenkinsPackError("Jenkins credential Key must contain an object")
    return value


def _nonempty(value: Any, name: str, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise JenkinsPackError(f"{name} must be a non-empty string of at most {maximum} characters")
    if any(ord(character) < 32 for character in value):
        raise JenkinsPackError(f"{name} contains a control character")
    return value


def _integer(params: dict[str, Any], name: str, default: int, minimum: int, maximum: int) -> int:
    value = params.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise JenkinsPackError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _boolean(params: dict[str, Any], name: str, default: bool = False) -> bool:
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise JenkinsPackError(f"{name} must be a boolean")
    return value


def _resource_path(value: Any, name: str = "job_path") -> tuple[str, list[str]]:
    value = _nonempty(value, name, 512)
    if value.startswith("/") or value.endswith("/") or "\\" in value:
        raise JenkinsPackError(f"{name} must be a slash-separated Jenkins full name")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise JenkinsPackError(f"{name} contains an unsafe path segment")
    return value, parts


def _job_route(value: Any) -> tuple[str, str]:
    full_name, parts = _resource_path(value)
    return "/" + "/".join(f"job/{quote(part, safe='')}" for part in parts), full_name


def _segment(value: Any, name: str) -> str:
    value = _nonempty(value, name, 256)
    if value in {".", ".."} or "/" in value or "\\" in value:
        raise JenkinsPackError(f"{name} must be one safe resource name")
    return quote(value, safe="")


def _build_number(params: dict[str, Any]) -> int:
    return _integer(params, "build_number", 0, 1, 2**31 - 1)


def _confirmation(params: dict[str, Any], expected: str) -> None:
    if params.get("confirmation") != expected:
        raise JenkinsPackError(f"confirmation must exactly equal '{expected}'")


def _xml_config(params: dict[str, Any]) -> bytes:
    value = params.get("config_xml")
    if not isinstance(value, str) or not value.strip():
        raise JenkinsPackError("config_xml must be a non-empty XML string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise JenkinsPackError("config_xml must be valid UTF-8 text") from None
    if len(encoded) > MAX_XML_BYTES:
        raise JenkinsPackError("config_xml exceeds the 1 MiB action limit")
    if "\x00" in value or _XML_DANGEROUS.search(value):
        raise JenkinsPackError("config_xml contains a prohibited declaration or inclusion")
    try:
        root = ET.fromstring(encoded)
    except ET.ParseError:
        raise JenkinsPackError("config_xml is not well-formed XML") from None
    if not isinstance(root.tag, str) or root.tag.startswith("{") or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,255}", root.tag):
        raise JenkinsPackError("config_xml has an unsupported root element")
    if any(
        isinstance(element.tag, str)
        and element.tag.startswith("{http://www.w3.org/2001/XInclude}")
        for element in root.iter()
    ):
        raise JenkinsPackError("config_xml contains a prohibited declaration or inclusion")
    return encoded


def _valid_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    if len(hostname) > 253 or hostname.endswith("."):
        return False
    return all(
        len(label) <= 63 and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in hostname.split(".")
    )


@contextmanager
def _tls_verify(ca_cert: str | None) -> Iterator[bool | str]:
    if ca_cert is None:
        yield True
        return
    with tempfile.TemporaryDirectory(prefix="attune-jenkins-") as directory:
        path = Path(directory, "ca.pem")
        path.write_text(ca_cert, encoding="utf-8")
        os.chmod(path, 0o600)
        yield str(path)


class JenkinsClient:
    def __init__(self, credential: dict[str, Any], timeout_seconds: int):
        base_url = credential.get("base_url")
        if not isinstance(base_url, str) or not base_url.isascii():
            raise JenkinsPackError("credential base_url must be an ASCII HTTPS URL")
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise JenkinsPackError("credential base_url must be an HTTPS URL without credentials, query, or fragment")
        if not _valid_hostname(parsed.hostname):
            raise JenkinsPackError("credential base_url hostname is invalid or ambiguous")
        try:
            parsed.port
        except ValueError:
            raise JenkinsPackError("credential base_url has an invalid port") from None
        if any(token in parsed.path for token in ("%", "\\", "//")):
            raise JenkinsPackError("credential base_url path contains ambiguous encoding")
        path_parts = [part for part in parsed.path.split("/") if part]
        if any(part in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9._~-]+", part) for part in path_parts):
            raise JenkinsPackError("credential base_url path is not a safe Jenkins context path")
        verify_tls = credential.get("verify_tls", True)
        if verify_tls is not True:
            raise JenkinsPackError("credential verify_tls must be true")
        ca_cert = credential.get("ca_cert")
        if ca_cert is not None and (not isinstance(ca_cert, str) or not ca_cert.strip() or len(ca_cert) > 1024 * 1024):
            raise JenkinsPackError("credential ca_cert must be a non-empty PEM string of at most 1 MiB")

        username = credential.get("username")
        api_token = credential.get("api_token")
        password = credential.get("password")
        if api_token is not None and password is not None:
            raise JenkinsPackError("credential must not contain both api_token and password")
        secret = api_token if api_token is not None else password
        if (username is None) != (secret is None):
            raise JenkinsPackError("credential username and api_token or password must be supplied together")
        if username is not None:
            _nonempty(username, "credential username", 256)
            _nonempty(secret, "credential secret", 4096)
            if ":" in username:
                raise JenkinsPackError("credential username must not contain ':' for HTTP Basic authentication")

        build_tokens = credential.get("build_tokens", {})
        if not isinstance(build_tokens, dict) or any(
            not isinstance(key, str) or not key or len(key) > 256
            or not isinstance(value, str) or not value or len(value) > 4096
            or any(ord(character) < 32 for character in key + value)
            for key, value in build_tokens.items()
        ):
            raise JenkinsPackError("credential build_tokens must map non-empty names to non-empty tokens")

        self.base_url = base_url.rstrip("/")
        self.context_path = parsed.path.rstrip("/")
        self.origin = (parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or 443)
        self.timeout_seconds = timeout_seconds
        self.ca_cert = ca_cert
        self.auth_kind = "api_token" if api_token is not None else "password" if password is not None else "anonymous"
        self.build_tokens = build_tokens
        self.session = requests.Session()
        if username is not None:
            self.session.auth = (username, secret)
        self.crumb_header: tuple[str, str] | None = None
        self.crumb_used = False
        self.jenkins_version: str | None = None
        self.last_status: int | None = None

    def close(self) -> None:
        self.session.close()

    def _open(self, method: str, path: str, *, params: dict[str, Any] | None = None, data: Any = None, headers: dict[str, str] | None = None) -> requests.Response:
        if not path.startswith("/") or path.startswith("//"):
            raise JenkinsPackError("internal Jenkins endpoint is invalid")
        request_headers = {"Accept": "application/json", **(headers or {})}
        try:
            with _tls_verify(self.ca_cert) as verify:
                response = self.session.request(
                    method,
                    self.base_url + path,
                    params=params or {},
                    data=data,
                    headers=request_headers,
                    timeout=(min(self.timeout_seconds, 15), self.timeout_seconds),
                    verify=verify,
                    allow_redirects=False,
                    stream=True,
                )
        except requests.RequestException as exc:
            raise JenkinsPackError(f"Jenkins request failed ({type(exc).__name__})") from None
        self.last_status = response.status_code
        version = response.headers.get("X-Jenkins")
        if version:
            self.jenkins_version = version[:128]
        return response

    @staticmethod
    def _read_limited(response: requests.Response, maximum: int, label: str) -> bytes:
        content_length = response.headers.get("Content-Length")
        if content_length and content_length.isdigit() and int(content_length) > maximum:
            raise JenkinsPackError(f"Jenkins {label} exceeded the action size limit")
        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                total += len(chunk)
                if total > maximum:
                    raise JenkinsPackError(f"Jenkins {label} exceeded the action size limit")
                chunks.append(chunk)
        except requests.RequestException as exc:
            raise JenkinsPackError(f"Jenkins response failed ({type(exc).__name__})") from None
        return b"".join(chunks)

    def _json_response(self, response: requests.Response, expected: set[int], *, allow_404: bool = False) -> Any:
        try:
            if response.status_code == 404 and allow_404:
                return None
            if response.status_code not in expected:
                raise JenkinsPackError(f"Jenkins returned HTTP {response.status_code}")
            body = self._read_limited(response, MAX_JSON_BYTES, "JSON response")
            if not body:
                return {}
            try:
                value = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise JenkinsPackError("Jenkins returned an invalid JSON response") from None
            return value
        finally:
            response.close()

    def get_json(self, path: str, *, params: dict[str, Any] | None = None, allow_404: bool = False) -> Any:
        return self._json_response(self._open("GET", path, params=params), {200}, allow_404=allow_404)

    def _ensure_crumb(self) -> None:
        if self.auth_kind != "password" or self.crumb_header is not None:
            return
        response = self._open("GET", "/crumbIssuer/api/json")
        if response.status_code == 404:
            response.close()
            self.crumb_header = ("", "")
            return
        value = self._json_response(response, {200})
        if not isinstance(value, dict):
            raise JenkinsPackError("Jenkins returned an invalid crumb response")
        field = value.get("crumbRequestField")
        crumb = value.get("crumb")
        if not isinstance(field, str) or not _HEADER_NAME.fullmatch(field) or not isinstance(crumb, str) or not crumb or any(ord(c) < 32 for c in crumb):
            raise JenkinsPackError("Jenkins returned an invalid crumb response")
        self.crumb_header = (field, crumb)

    def post(self, path: str, *, params: dict[str, Any] | None = None, data: Any = None, content_type: str | None = None, expected: set[int] | None = None) -> requests.Response:
        self._ensure_crumb()
        headers: dict[str, str] = {}
        if self.crumb_header and self.crumb_header[0]:
            headers[self.crumb_header[0]] = self.crumb_header[1]
            self.crumb_used = True
        if content_type:
            headers["Content-Type"] = content_type
        response = self._open("POST", path, params=params, data=data, headers=headers)
        accepted = expected or {200, 201, 204, 302, 303}
        if response.status_code not in accepted:
            status = response.status_code
            response.close()
            raise JenkinsPackError(f"Jenkins returned HTTP {status}")
        return response

    def post_empty(self, path: str, **kwargs: Any) -> dict[str, Any]:
        response = self.post(path, **kwargs)
        status = response.status_code
        response.close()
        return {"changed": True, "http_status": status}

    def queue_id_from_location(self, location: str | None) -> int | None:
        if not location or not isinstance(location, str):
            return None
        parsed = urlsplit(location)
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            return None
        if parsed.scheme or parsed.netloc:
            try:
                origin = (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port or 443)
            except ValueError:
                return None
            if origin != self.origin:
                return None
        match = re.fullmatch(re.escape(self.context_path) + r"/queue/item/([1-9][0-9]*)/?", parsed.path)
        return int(match.group(1)) if match else None

    def metadata(self) -> dict[str, Any]:
        return {
            "jenkins_version": self.jenkins_version,
            "authentication": self.auth_kind,
            "crumb_used": self.crumb_used,
            "http_status": self.last_status,
        }


def _job_json(client: JenkinsClient, job_path: Any) -> tuple[dict[str, Any], str, str]:
    route, full_name = _job_route(job_path)
    value = client.get_json(route + "/api/json")
    if not isinstance(value, dict):
        raise JenkinsPackError("Jenkins returned an invalid job response")
    if "fullName" in value and value["fullName"] != full_name:
        raise JenkinsPackError("Jenkins job identity did not match the requested job_path")
    return value, route, full_name


def _queue_json(client: JenkinsClient, queue_id: int, *, allow_404: bool = False) -> dict[str, Any] | None:
    value = client.get_json(f"/queue/item/{queue_id}/api/json", allow_404=allow_404)
    if value is not None and not isinstance(value, dict):
        raise JenkinsPackError("Jenkins returned an invalid queue item response")
    if value is not None and "id" in value and value["id"] != queue_id:
        raise JenkinsPackError("Jenkins queue identity did not match the requested queue_id")
    return value


def _queue_state(item: dict[str, Any]) -> str:
    if item.get("cancelled") is True:
        return "cancelled"
    if isinstance(item.get("executable"), dict) and isinstance(item["executable"].get("number"), int):
        return "started"
    return "queued"


def _queue_task_matches(client: JenkinsClient, item: dict[str, Any], expected_job: str) -> bool:
    task = item.get("task")
    if not isinstance(task, dict):
        return False
    if task.get("fullName") == expected_job:
        return True
    if "/" not in expected_job and task.get("name") == expected_job:
        return True
    task_url = task.get("url")
    if not isinstance(task_url, str):
        return False
    parsed = urlsplit(task_url)
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        return False
    if parsed.scheme or parsed.netloc:
        try:
            origin = (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port or 443)
        except ValueError:
            return False
        if origin != client.origin:
            return False
    route, _ = _job_route(expected_job)
    return parsed.path.rstrip("/") == client.context_path + route


def _wait_queue(client: JenkinsClient, queue_id: int, wait_seconds: int, poll_interval: int, expected_job: str | None = None) -> dict[str, Any]:
    deadline = time.monotonic() + wait_seconds
    while True:
        item = _queue_json(client, queue_id, allow_404=True)
        if item is None:
            raise JenkinsPackError("queue item is no longer available; build identity is unknown and was not guessed")
        if expected_job is not None and not _queue_task_matches(client, item, expected_job):
            raise JenkinsPackError("queue item identity did not match the triggered job_path")
        state = _queue_state(item)
        if state != "queued":
            return {"state": state, "queue_id": queue_id, "item": item}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"state": "timed_out", "queue_id": queue_id, "item": item}
        time.sleep(min(poll_interval, remaining))


def _build_json(client: JenkinsClient, job_path: Any, build_number: int, *, allow_404: bool = False) -> tuple[dict[str, Any] | None, str, str]:
    route, full_name = _job_route(job_path)
    value = client.get_json(f"{route}/{build_number}/api/json", allow_404=allow_404)
    if value is not None and not isinstance(value, dict):
        raise JenkinsPackError("Jenkins returned an invalid build response")
    if value is not None and "number" in value and value["number"] != build_number:
        raise JenkinsPackError("Jenkins build identity did not match the requested build_number")
    return value, route, full_name


def _wait_build(client: JenkinsClient, job_path: Any, build_number: int, wait_seconds: int, poll_interval: int) -> dict[str, Any]:
    deadline = time.monotonic() + wait_seconds
    while True:
        build, _, full_name = _build_json(client, job_path, build_number)
        assert build is not None
        if build.get("building") is False:
            return {"state": "completed", "job_path": full_name, "build_number": build_number, "build": build}
        if build.get("building") is not True:
            raise JenkinsPackError("Jenkins build response omitted a boolean building state")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"state": "timed_out", "job_path": full_name, "build_number": build_number, "build": build}
        time.sleep(min(poll_interval, remaining))


def _flatten_jobs(items: Any, result: list[dict[str, Any]]) -> None:
    if not isinstance(items, list):
        raise JenkinsPackError("Jenkins returned an invalid jobs response")
    for item in items:
        if not isinstance(item, dict):
            raise JenkinsPackError("Jenkins returned an invalid jobs response")
        copy = {key: value for key, value in item.items() if key != "jobs"}
        result.append(copy)
        if "jobs" in item:
            _flatten_jobs(item["jobs"], result)


def _artifact_items(client: JenkinsClient, job_path: Any, build_number: int) -> tuple[list[dict[str, Any]], str, str]:
    route, full_name = _job_route(job_path)
    value = client.get_json(f"{route}/{build_number}/api/json", params={"tree": "artifacts[fileName,relativePath]"})
    artifacts = value.get("artifacts") if isinstance(value, dict) else None
    if not isinstance(artifacts, list) or any(not isinstance(item, dict) for item in artifacts):
        raise JenkinsPackError("Jenkins returned an invalid artifact list")
    return artifacts, route, full_name


def _artifact_route(relative_path: Any) -> tuple[str, list[str]]:
    path, parts = _resource_path(relative_path, "artifact_path")
    return path, [quote(part, safe="") for part in parts]


def _destination(relative: Any) -> Path:
    value, parts = _resource_path(relative, "destination")
    del value
    root_value = os.environ.get("ATTUNE_ARTIFACTS_DIR")
    if not root_value:
        raise JenkinsPackError("ATTUNE_ARTIFACTS_DIR is required for artifact downloads")
    root = Path(root_value)
    if not root.is_absolute() or not root.exists() or not root.is_dir() or root.is_symlink():
        raise JenkinsPackError("ATTUNE_ARTIFACTS_DIR must name an existing non-symlink absolute directory")
    root = root.resolve(strict=True)
    parent = root
    for part in parts[:-1]:
        parent = parent / part
        if parent.exists():
            if parent.is_symlink() or not parent.is_dir():
                raise JenkinsPackError("artifact destination parent is not a safe directory")
        else:
            parent.mkdir(mode=0o700)
        if root not in parent.resolve(strict=True).parents and parent.resolve(strict=True) != root:
            raise JenkinsPackError("artifact destination escapes ATTUNE_ARTIFACTS_DIR")
    target = parent / parts[-1]
    if target.exists() and (target.is_symlink() or target.is_dir()):
        raise JenkinsPackError("artifact destination is not a regular file path")
    return target


def _download_artifact(client: JenkinsClient, params: dict[str, Any]) -> dict[str, Any]:
    build_number = _build_number(params)
    requested, encoded_parts = _artifact_route(params.get("artifact_path"))
    artifacts, route, full_name = _artifact_items(client, params.get("job_path"), build_number)
    if requested not in {item.get("relativePath") for item in artifacts}:
        raise JenkinsPackError("artifact_path is not present in the build artifact list")
    target = _destination(params.get("destination"))
    maximum = _integer(params, "max_bytes", MAX_ARTIFACT_BYTES, 1, MAX_ARTIFACT_BYTES)
    response = client._open("GET", f"{route}/{build_number}/artifact/" + "/".join(encoded_parts), headers={"Accept": "application/octet-stream"})
    if response.status_code != 200:
        status = response.status_code
        response.close()
        raise JenkinsPackError(f"Jenkins returned HTTP {status}")
    length = response.headers.get("Content-Length")
    if length and length.isdigit() and int(length) > maximum:
        response.close()
        raise JenkinsPackError("Jenkins artifact exceeded max_bytes")
    temp_name: str | None = None
    total = 0
    digest = hashlib.sha256()
    try:
        with tempfile.NamedTemporaryFile(prefix=".attune-jenkins-", dir=target.parent, delete=False) as output:
            temp_name = output.name
            os.chmod(temp_name, 0o600)
            for chunk in response.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                total += len(chunk)
                if total > maximum:
                    raise JenkinsPackError("Jenkins artifact exceeded max_bytes")
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_name, target)
        temp_name = None
    except requests.RequestException as exc:
        raise JenkinsPackError(f"Jenkins artifact transfer failed ({type(exc).__name__})") from None
    except OSError:
        raise JenkinsPackError("artifact could not be written safely") from None
    finally:
        response.close()
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
    return {
        "job_path": full_name,
        "build_number": build_number,
        "artifact_path": requested,
        "destination": str(target),
        "bytes": total,
        "sha256": digest.hexdigest(),
    }


def _execute(client: JenkinsClient, operation: str, params: dict[str, Any]) -> Any:
    if operation == "server_info":
        value = client.get_json("/api/json", params={"tree": "nodeName,nodeDescription,numExecutors,mode,quietingDown,useCrumbs,useSecurity"})
        if not isinstance(value, dict):
            raise JenkinsPackError("Jenkins returned an invalid server response")
        if client.jenkins_version is None:
            raise JenkinsPackError("server did not return the Jenkins-identifying X-Jenkins header")
        return value

    if operation == "jobs_list":
        depth = _integer(params, "folder_depth", 3, 0, 10)
        fields = "name,fullName,url,color,_class"
        nested = fields
        for _ in range(depth):
            nested = f"{fields},jobs[{nested}]"
        value = client.get_json("/api/json", params={"tree": f"jobs[{nested}]"})
        result: list[dict[str, Any]] = []
        _flatten_jobs(value.get("jobs") if isinstance(value, dict) else None, result)
        return {"items": result, "count": len(result), "folder_depth": depth}

    if operation == "job_get":
        value, _, full_name = _job_json(client, params.get("job_path"))
        return {"job_path": full_name, "job": value}

    if operation in {"job_create", "job_update"}:
        route, full_name = _job_route(params.get("job_path"))
        if operation == "job_create":
            _confirmation(params, f"create job {full_name}")
            config = _xml_config(params)
            _, parts = _resource_path(full_name)
            parent_route = "/" + "/".join(f"job/{quote(part, safe='')}" for part in parts[:-1]) if len(parts) > 1 else ""
            response = client.post(parent_route + "/createItem", params={"name": parts[-1]}, data=config, content_type="application/xml")
        else:
            _confirmation(params, f"replace config {full_name}")
            config = _xml_config(params)
            response = client.post(route + "/config.xml", data=config, content_type="application/xml")
        status = response.status_code
        response.close()
        return {"changed": True, "job_path": full_name, "http_status": status}

    if operation in {"job_delete", "job_enable", "job_disable"}:
        _, route, full_name = _job_json(client, params.get("job_path"))
        if operation == "job_delete":
            _confirmation(params, f"delete job {full_name}")
            suffix = "/doDelete"
        else:
            suffix = "/enable" if operation == "job_enable" else "/disable"
        result = client.post_empty(route + suffix)
        return {**result, "job_path": full_name}

    if operation == "build_trigger":
        _, route, full_name = _job_json(client, params.get("job_path"))
        supplied = params.get("parameters", {})
        if not isinstance(supplied, dict) or len(supplied) > 100:
            raise JenkinsPackError("parameters must be an object with at most 100 entries")
        form: dict[str, str] = {}
        for key, value in supplied.items():
            _nonempty(key, "parameter name", 256)
            if not isinstance(value, (str, int, float, bool)) or isinstance(value, float) and not (-1e308 < value < 1e308):
                raise JenkinsPackError("parameter values must be finite JSON scalars")
            form[key] = str(value).lower() if isinstance(value, bool) else str(value)
            if len(form[key]) > 65536 or any(ord(c) < 9 for c in form[key]):
                raise JenkinsPackError("parameter value is too large or contains an invalid control character")
        query: dict[str, str] = {}
        token_name = params.get("build_token_name")
        if token_name is not None:
            token_name = _nonempty(token_name, "build_token_name", 256)
            if token_name not in client.build_tokens:
                raise JenkinsPackError("build_token_name was not found in the Jenkins credential Key")
            query["token"] = client.build_tokens[token_name]
        response = client.post(route + ("/buildWithParameters" if supplied else "/build"), params=query, data=form, content_type="application/x-www-form-urlencoded")
        status = response.status_code
        queue_id = client.queue_id_from_location(response.headers.get("Location"))
        response.close()
        if queue_id is None:
            return {"state": "accepted_identity_unknown", "job_path": full_name, "queue_id": None, "http_status": status, "retry_safe": False}
        if _boolean(params, "wait_for_start"):
            result = _wait_queue(
                client,
                queue_id,
                _integer(params, "max_wait_seconds", 300, 1, 3600),
                _integer(params, "poll_interval_seconds", 3, 1, 30),
                full_name,
            )
            result["job_path"] = full_name
            return result
        return {"state": "queued", "job_path": full_name, "queue_id": queue_id, "http_status": status, "retry_safe": False}

    if operation == "queue_list":
        value = client.get_json("/queue/api/json")
        items = value.get("items") if isinstance(value, dict) else None
        if not isinstance(items, list):
            raise JenkinsPackError("Jenkins returned an invalid queue response")
        return {"items": items, "count": len(items)}

    if operation in {"queue_get", "queue_wait", "queue_cancel"}:
        queue_id = _integer(params, "queue_id", 0, 1, 2**63 - 1)
        if operation == "queue_wait":
            return _wait_queue(
                client,
                queue_id,
                _integer(params, "max_wait_seconds", 300, 1, 3600),
                _integer(params, "poll_interval_seconds", 3, 1, 30),
            )
        item = _queue_json(client, queue_id)
        assert item is not None
        if operation == "queue_get":
            return {"state": _queue_state(item), "queue_id": queue_id, "item": item}
        expected_full_name, _ = _resource_path(params.get("job_path"))
        if not _queue_task_matches(client, item, expected_full_name):
            raise JenkinsPackError("queue item does not belong to the confirmed job_path")
        if _queue_state(item) != "queued":
            raise JenkinsPackError("queue item is no longer cancellable; no build was stopped")
        _confirmation(params, f"cancel queue {queue_id} for {expected_full_name}")
        response = client.post("/queue/cancelItem", params={"id": queue_id}, expected={204})
        response.close()
        return {"changed": True, "state": "cancelled", "queue_id": queue_id, "job_path": expected_full_name}

    if operation in {"build_get", "build_wait", "build_stop", "build_term", "build_kill"}:
        number = _build_number(params)
        if operation == "build_wait":
            return _wait_build(
                client,
                params.get("job_path"),
                number,
                _integer(params, "max_wait_seconds", 900, 1, 3600),
                _integer(params, "poll_interval_seconds", 5, 1, 30),
            )
        build, route, full_name = _build_json(client, params.get("job_path"), number)
        assert build is not None
        if operation == "build_get":
            return {"job_path": full_name, "build_number": number, "build": build}
        if build.get("building") is not True:
            raise JenkinsPackError("confirmed build is not running; no termination request was sent")
        verb = operation.removeprefix("build_")
        _confirmation(params, f"{verb} build {full_name}#{number}")
        result = client.post_empty(f"{route}/{number}/{verb}")
        return {**result, "job_path": full_name, "build_number": number, "termination": verb}

    if operation == "console_log":
        number = _build_number(params)
        route, full_name = _job_route(params.get("job_path"))
        start = _integer(params, "start", 0, 0, 2**63 - 1)
        maximum = _integer(params, "max_bytes", MAX_LOG_BYTES, 1, MAX_LOG_BYTES)
        response = client._open("GET", f"{route}/{number}/logText/progressiveText", params={"start": start}, headers={"Accept": "text/plain"})
        if response.status_code != 200:
            status = response.status_code
            response.close()
            raise JenkinsPackError(f"Jenkins returned HTTP {status}")
        try:
            body = client._read_limited(response, maximum, "console log chunk")
            size_header = response.headers.get("X-Text-Size")
            if not size_header or not size_header.isdigit():
                raise JenkinsPackError("Jenkins progressive log response omitted X-Text-Size")
            next_start = int(size_header)
            if next_start < start:
                raise JenkinsPackError("Jenkins progressive log offset moved backwards")
            more = response.headers.get("X-More-Data", "false").lower() == "true"
        finally:
            response.close()
        return {"job_path": full_name, "build_number": number, "start": start, "next_start": next_start, "more": more, "text": body.decode("utf-8", errors="replace")}

    if operation == "artifact_list":
        number = _build_number(params)
        artifacts, _, full_name = _artifact_items(client, params.get("job_path"), number)
        return {"job_path": full_name, "build_number": number, "items": artifacts, "count": len(artifacts)}

    if operation == "artifact_download":
        return _download_artifact(client, params)

    if operation in {"nodes_list", "node_get", "node_offline"}:
        if operation == "nodes_list":
            value = client.get_json("/computer/api/json", params={"tree": "computer[displayName,offline,temporarilyOffline,idle,numExecutors,offlineCauseReason]"})
            items = value.get("computer") if isinstance(value, dict) else None
            if not isinstance(items, list):
                raise JenkinsPackError("Jenkins returned an invalid node response")
            return {"items": items, "count": len(items)}
        node_name = _nonempty(params.get("node_name"), "node_name", 256)
        route = f"/computer/{_segment(node_name, 'node_name')}"
        value = client.get_json(route + "/api/json")
        if not isinstance(value, dict):
            raise JenkinsPackError("Jenkins returned an invalid node response")
        if operation == "node_get":
            return {"node_name": node_name, "node": value}
        _confirmation(params, f"offline node {node_name}")
        if value.get("temporarilyOffline") is True:
            return {"changed": False, "node_name": node_name, "temporarily_offline": True}
        message = _nonempty(params.get("message"), "message", 256)
        client.post_empty(route + "/changeOfflineCause", params={"offlineMessage": message})
        after = client.get_json(route + "/api/json")
        if not isinstance(after, dict) or after.get("temporarilyOffline") is not True:
            raise JenkinsPackError("Jenkins did not confirm the node was marked temporarily offline")
        return {"changed": True, "node_name": node_name, "temporarily_offline": True}

    if operation == "plugins_list":
        fields = "active,bundled,deleted,detached,disabled,enabled,longName,pinned,shortName,supportsDynamicLoad,url,version"
        value = client.get_json("/pluginManager/api/json", params={"tree": f"plugins[{fields}]"})
        items = value.get("plugins") if isinstance(value, dict) else None
        if not isinstance(items, list):
            raise JenkinsPackError("Jenkins returned an invalid plugin response")
        return {"items": items, "count": len(items)}

    raise JenkinsPackError("unsupported Jenkins action")


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    timeout = _integer(params, "timeout_seconds", 30, 1, 120)
    credential = _fetch_key(params.get("credential_key", DEFAULT_CREDENTIAL_KEY))
    client = JenkinsClient(credential, timeout)
    try:
        data = _execute(client, operation, params)
        return {"operation": operation, "data": data, "meta": client.metadata()}
    finally:
        client.close()
