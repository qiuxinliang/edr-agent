#!/usr/bin/env python3
"""
独立安装器：POST {EDR_API_BASE}/api/v1/enroll，根据响应生成 agent.toml。

环境变量（必填）：
  EDR_API_BASE      平台 REST 根 URL，如 http://127.0.0.1:8080（无尾斜杠）
  EDR_ENROLL_TOKEN  注册 Token 明文

可选：
  EDR_OUTPUT              输出路径，默认当前目录 agent.toml
  EDR_AGENT_VERSION       默认读取 VERSION；再否则 unknown
  EDR_AGENT_EXECUTABLE    指定用于 --config-test 的 Agent 二进制
  EDR_OVERRIDE_SERVER_ADDR  覆盖响应中的 server_addr 写入 [server].address
  EDR_CA_CERT / EDR_CLIENT_CERT / EDR_CLIENT_KEY / EDR_CLIENT_CSR
  EDR_INSECURE_TLS=1      跳过 TLS 证书校验（仅调试）

命令行：
  python3 edr_agent_install.py [--output PATH] [--dry-run] [--generate-only]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional


_ENROLL_SECRET_FIELDS = {
    "platform_bearer_token",
    "agent_access_token",
    "access_token",
    "rest_bearer_token",
    "bearer_token",
    "request_signing_secret",
}


class ConfigValidationError(RuntimeError):
    pass


def _toml_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _sanitize_bearer_token(value: Any) -> str:
    token = str(value or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not token:
        return ""
    if len(token) > 480:
        print("enroll response bearer token exceeds Agent configuration limit", file=sys.stderr)
        sys.exit(1)
    if any(ord(ch) <= 32 or ord(ch) == 127 for ch in token):
        print("enroll response bearer token contains whitespace or control characters", file=sys.stderr)
        sys.exit(1)
    return token


def _bearer_from_enroll(data: Dict[str, Any]) -> str:
    for key in ("platform_bearer_token", "agent_access_token", "access_token", "rest_bearer_token", "bearer_token"):
        token = _sanitize_bearer_token(data.get(key))
        if token:
            return token
    return ""


def _redact_enroll_payload(raw: str) -> str:
    try:
        obj = json.loads(raw)
    except Exception:
        return "<non-JSON response omitted>"

    def redact(value: Any) -> None:
        if isinstance(value, dict):
            for k, v in list(value.items()):
                if k in _ENROLL_SECRET_FIELDS:
                    value[k] = "<redacted>"
                else:
                    redact(v)
        elif isinstance(value, list):
            for item in value:
                redact(item)

    redact(obj)
    return json.dumps(obj, ensure_ascii=False)


def _normalize_api_base(raw: str) -> tuple[str, str, str]:
    value = (raw or "").strip().rstrip("/")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        print(f"EDR_API_BASE must be an absolute http(s) URL: {raw}", file=sys.stderr)
        sys.exit(2)
    path = parsed.path.rstrip("/")
    lower = path.lower()
    if lower.endswith("/api/v1/enroll"):
        path = path[: -len("/api/v1/enroll")]
    elif lower.endswith("/api/v1"):
        path = path[: -len("/api/v1")]
    server_base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path.rstrip("/"), "", "")).rstrip("/")
    return server_base, server_base + "/api/v1", server_base + "/api/v1/enroll"


def _normalize_enroll_result(data: Dict[str, Any], normalized_rest_base: str) -> Dict[str, Any]:
    endpoint_id = str(data.get("endpoint_id") or "").strip()
    tenant_id = str(data.get("tenant_id") or "").strip()
    server_addr = str(data.get("server_addr") or "").strip()
    if not endpoint_id or not tenant_id or not server_addr:
        raise ValueError("missing endpoint_id, tenant_id or server_addr")

    request_signing_enabled = data.get("request_signing_enabled", False)
    request_signing_required = data.get("request_signing_required", False)
    if not isinstance(request_signing_enabled, bool) or not isinstance(request_signing_required, bool):
        raise ValueError("request signing flags must be booleans")
    if request_signing_required and not request_signing_enabled:
        raise ValueError("request signing cannot be required while disabled")
    request_signing_key_id = str(data.get("request_signing_key_id") or "").strip()
    request_signing_secret = str(data.get("request_signing_secret") or "").strip()
    if request_signing_enabled or request_signing_required:
        if not request_signing_key_id or not request_signing_secret:
            raise ValueError("request signing is enabled but key_id or secret is missing")
        if len(request_signing_key_id) >= 128 or len(request_signing_secret) >= 256:
            raise ValueError("request signing credentials exceed Agent configuration limits")
        if any(ord(ch) <= 32 or ord(ch) == 127 for ch in request_signing_key_id + request_signing_secret):
            raise ValueError("request signing credentials contain whitespace or control characters")

    override = os.environ.get("EDR_OVERRIDE_SERVER_ADDR", "").strip()
    if override:
        server_addr = override
    return {
        "endpoint_id": endpoint_id,
        "tenant_id": tenant_id,
        "server_addr": server_addr,
        "rest_base": str(data.get("rest_base_url") or normalized_rest_base).strip().rstrip("/"),
        "rest_bearer_token": _bearer_from_enroll(data),
        "ca_cert": data.get("ca_cert") or "",
        "client_cert": data.get("client_cert") or "",
        "request_signing_enabled": request_signing_enabled,
        "request_signing_required": request_signing_required,
        "request_signing_key_id": request_signing_key_id,
        "request_signing_secret": request_signing_secret,
    }


def _emit_toml(
    server_addr: str,
    endpoint_id: str,
    tenant_id: str,
    rest_base: str,
    rest_bearer_token: str,
    ca_cert_path: str,
    client_cert_path: str,
    client_key_path: str,
    client_key_provider: str,
    client_cert_store: str,
    client_cert_thumbprint: str,
    pkcs11_module: str,
    pkcs11_key_uri: str,
    tpm_key_uri: str,
    request_signing_enabled: bool,
    request_signing_key_id: str,
    request_signing_secret: str,
    install_dir: str = "",
) -> str:
    lines = [
        "# Generated by edr_agent_install.py",
        "",
        "[server]",
        f'address              = "{_toml_escape(server_addr)}"',
        f'ca_cert              = "{_toml_escape(ca_cert_path)}"',
        f'client_cert          = "{_toml_escape(client_cert_path)}"',
        f'client_key           = "{_toml_escape(client_key_path)}"',
        f'client_key_provider  = "{_toml_escape(client_key_provider)}"',
        f'client_cert_store    = "{_toml_escape(client_cert_store)}"',
        f'client_cert_thumbprint = "{_toml_escape(client_cert_thumbprint)}"',
        f'pkcs11_module        = "{_toml_escape(pkcs11_module)}"',
        f'pkcs11_key_uri       = "{_toml_escape(pkcs11_key_uri)}"',
        f'tpm_key_uri          = "{_toml_escape(tpm_key_uri)}"',
        "connect_timeout_s    = 10",
        "keepalive_interval_s = 30",
        "",
        "[agent]",
        f'endpoint_id          = "{_toml_escape(endpoint_id)}"',
        f'tenant_id            = "{_toml_escape(tenant_id)}"',
        "",
        "[platform]",
        f'rest_base_url        = "{_toml_escape(rest_base)}"',
        'rest_user_id         = ""',
        f'rest_bearer_token    = "{_toml_escape(rest_bearer_token)}"',
        "http2_enabled        = false",
        "http2_require        = false",
        "control_stream_enabled = true",
        "long_poll_fallback   = true",
        "report_events_v2_enabled = true",
        'data_plane_encoding  = "protobuf"',
        'data_plane_compression = "identity"',
        'control_dict_version = "edr-zstd-dict-v1"',
        'control_schema_version = "edr-control-schema-v1"',
        'control_profile_id   = "default-http1-protobuf"',
        "",
        "[platform.request_signing]",
        f"enabled              = {str(request_signing_enabled).lower()}",
        f'key_id               = "{_toml_escape(request_signing_key_id)}"',
        f'secret               = "{_toml_escape(request_signing_secret)}"',
        "",
    ]
    # 若安装目录已打包检测规则（package_bundled_layout.sh 落在 rules/{shellcode,webshell}），
    # 把规则目录写成绝对路径，避免依赖进程 CWD 的开发态相对默认值。
    if install_dir:
        base = Path(install_dir).expanduser().resolve()
        sc_dir = base / "rules" / "shellcode"
        ws_dir = base / "rules" / "webshell"
        if sc_dir.is_dir():
            lines += [
                "[shellcode_detector]",
                f'yara_rules_dir       = "{_toml_escape(str(sc_dir))}"',
                "yara_rules_reload_interval_s = 300",
                "",
            ]
        if ws_dir.is_dir():
            lines += [
                "[webshell_detector]",
                f'webshell_rules_dir   = "{_toml_escape(str(ws_dir))}"',
                "",
            ]
    return "\n".join(lines)


def _detect_os() -> str:
    plat = sys.platform.lower()
    if plat.startswith("win"):
        return "windows"
    if plat == "darwin":
        return "darwin"
    return "linux"


def _resolve_agent_version(output_path: str) -> str:
    env_version = os.environ.get("EDR_AGENT_VERSION", "").strip()
    if env_version:
        return env_version

    dirs = [
        Path(__file__).resolve().parent,
        Path(__file__).resolve().parent.parent,
    ]
    if output_path:
        dirs.append(Path(output_path).expanduser().resolve().parent)
    dirs.append(Path.cwd())

    seen = set()
    for directory in dirs:
        key = str(directory)
        if key in seen:
            continue
        seen.add(key)
        version_file = directory / "VERSION"
        try:
            version = version_file.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if version:
            return version

    return "unknown"


def _hostname() -> str:
    try:
        return socket.gethostname() or "unknown"
    except OSError:
        return "unknown"


def enroll(api_base: str, token: str, agent_version: str, csr_pem: str) -> Dict[str, Any]:
    _, normalized_rest_base, url = _normalize_api_base(api_base)
    body = {
        "token": token,
        "hostname": _hostname(),
        "os": _detect_os(),
        "arch": platform.machine() or "",
        "agent_version": agent_version,
        "ip": "",
        "csr_pem": csr_pem,
    }
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    ctx = None
    if os.environ.get("EDR_INSECURE_TLS") == "1":
        ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
            raw = resp.read().decode("utf-8")
            status = int(resp.status)
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        print(f"enroll HTTP {e.code}: {_redact_enroll_payload(err_body)}", file=sys.stderr)
        sys.exit(1)

    if status != 201:
        print(f"enroll unexpected status {status}: {_redact_enroll_payload(raw)}", file=sys.stderr)
        sys.exit(1)

    env = json.loads(raw)
    if env.get("code") and env.get("code") != "OK":
        print(f"enroll error: {env.get('message', _redact_enroll_payload(raw))}", file=sys.stderr)
        sys.exit(1)
    data_obj = env.get("data") or {}
    if not isinstance(data_obj, dict):
        print("enroll response data must be an object", file=sys.stderr)
        sys.exit(1)
    try:
        return _normalize_enroll_result(data_obj, normalized_rest_base)
    except ValueError as exc:
        print(f"enroll response invalid: {exc}", file=sys.stderr)
        sys.exit(1)


def _default_cert_paths() -> tuple[str, str, str]:
    if sys.platform.lower().startswith("win"):
        base = r"C:\Program Files\FDSecurity\certs"
    else:
        base = os.path.abspath("certs")
    return (
        os.environ.get("EDR_CA_CERT", os.path.join(base, "ca.pem")),
        os.environ.get("EDR_CLIENT_CERT", os.path.join(base, "client.pem")),
        os.environ.get("EDR_CLIENT_KEY", os.path.join(base, "client-key.pem")),
    )


def _default_csr_path(key_path: str) -> str:
    return os.environ.get("EDR_CLIENT_CSR", os.path.join(os.path.dirname(os.path.abspath(key_path)), "client.csr.pem"))


def _run_checked(args: list[str]) -> None:
    try:
        subprocess.run(args, check=True)
    except FileNotFoundError:
        print("openssl is required to generate the endpoint private key and CSR", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"command failed ({e.returncode}): {' '.join(args)}", file=sys.stderr)
        sys.exit(e.returncode or 1)


def _normalize_key_provider() -> str:
    provider = (os.environ.get("EDR_KEY_PROVIDER") or "pem").strip().lower()
    if provider == "file":
        provider = "pem"
    if provider not in {"pem", "cng", "tpm", "pkcs11"}:
        print("EDR_KEY_PROVIDER must be one of pem|cng|tpm|pkcs11", file=sys.stderr)
        sys.exit(2)
    return provider


def _ensure_cng_csr(csr_path: str, provider: str) -> str:
    if not sys.platform.lower().startswith("win"):
        print("EDR_KEY_PROVIDER=cng requires Windows certreq.exe", file=sys.stderr)
        sys.exit(2)
    csr_parent = os.path.dirname(os.path.abspath(csr_path))
    if csr_parent:
        os.makedirs(csr_parent, exist_ok=True)
    cn = _hostname().replace("/", "-").replace("\\", "-").replace('"', "") or "edr-agent"
    key_name = os.environ.get("EDR_CNG_KEY_NAME", f"EDR-Agent-{cn}")
    provider_name = os.environ.get("EDR_CNG_PROVIDER_NAME")
    if not provider_name:
        provider_name = "Microsoft Platform Crypto Provider" if provider == "tpm" else "Microsoft Software Key Storage Provider"
    inf_path = str(Path(csr_path).with_suffix(".inf"))
    inf = f"""[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN={cn}"
KeyAlgorithm = RSA
KeyLength = 3072
HashAlgorithm = SHA256
ProviderName = "{provider_name}"
KeyContainer = "{key_name}"
MachineKeySet = TRUE
Exportable = FALSE
KeyExportPolicy = 0
KeySpec = 1
RequestType = PKCS10
Silent = TRUE

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2
"""
    with open(inf_path, "w", encoding="utf-8") as f:
        f.write(inf)
    _run_checked(["certreq.exe", "-new", "-machine", inf_path, csr_path])
    with open(csr_path, "r", encoding="utf-8") as f:
        return f.read()


def _ensure_external_key_csr(csr_path: str, provider: str) -> str:
    csr_parent = os.path.dirname(os.path.abspath(csr_path))
    if csr_parent:
        os.makedirs(csr_parent, exist_ok=True)
    cn = _hostname().replace("/", "-").replace("\\", "-") or "edr-agent"
    if provider == "pkcs11":
        key_uri = os.environ.get("EDR_PKCS11_KEY_URI", "").strip()
        if not key_uri:
            print("EDR_PKCS11_KEY_URI is required for EDR_KEY_PROVIDER=pkcs11", file=sys.stderr)
            sys.exit(2)
        mode = os.environ.get("EDR_PKCS11_OPENSSL_MODE", "engine").strip().lower()
        module = os.environ.get("EDR_PKCS11_MODULE", "").strip()
        if mode == "provider":
            args = ["openssl", "req", "-new", "-provider", "default"]
            if module:
                args += ["-provider-path", module]
            args += ["-provider", "pkcs11", "-key", key_uri, "-out", csr_path, "-subj", f"/CN={cn}"]
            _run_checked(args)
        else:
            _run_checked(["openssl", "req", "-new", "-engine", "pkcs11", "-keyform", "engine", "-key", key_uri, "-out", csr_path, "-subj", f"/CN={cn}"])
    elif provider == "tpm":
        key_uri = os.environ.get("EDR_TPM_KEY_URI", "").strip()
        if not key_uri:
            print("EDR_TPM_KEY_URI is required for OpenSSL TPM provider mode", file=sys.stderr)
            sys.exit(2)
        tpm_provider = os.environ.get("EDR_OPENSSL_TPM_PROVIDER", "tpm2").strip() or "tpm2"
        _run_checked(["openssl", "req", "-new", "-provider", "default", "-provider", tpm_provider, "-key", key_uri, "-out", csr_path, "-subj", f"/CN={cn}"])
    with open(csr_path, "r", encoding="utf-8") as f:
        return f.read()


def _ensure_csr(key_path: str, csr_path: str, provider: str) -> str:
    if provider == "cng" or (provider == "tpm" and not os.environ.get("EDR_TPM_KEY_URI")):
        return _ensure_cng_csr(csr_path, provider)
    if provider in {"pkcs11", "tpm"}:
        return _ensure_external_key_csr(csr_path, provider)
    parent = os.path.dirname(os.path.abspath(key_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    csr_parent = os.path.dirname(os.path.abspath(csr_path))
    if csr_parent:
        os.makedirs(csr_parent, exist_ok=True)
    if not os.path.exists(key_path):
        _run_checked(["openssl", "genrsa", "-out", key_path, "3072"])
    cn = _hostname().replace("/", "-").replace("\\", "-") or "edr-agent"
    _run_checked(["openssl", "req", "-new", "-key", key_path, "-out", csr_path, "-subj", f"/CN={cn}"])
    with open(csr_path, "r", encoding="utf-8") as f:
        return f.read()


def _pem_thumbprint_sha1(pem_text: str) -> str:
    if "-----BEGIN CERTIFICATE-----" not in pem_text:
        return ""
    import base64
    import hashlib

    body = pem_text.split("-----BEGIN CERTIFICATE-----", 1)[1].split("-----END CERTIFICATE-----", 1)[0]
    der = base64.b64decode("".join(body.split()))
    return hashlib.sha1(der).hexdigest().upper()


def _accept_cng_cert(cert_path: str, provider: str) -> None:
    if provider not in {"cng", "tpm"} or not sys.platform.lower().startswith("win"):
        return
    _run_checked(["certreq.exe", "-accept", "-machine", cert_path])


def _write_pem(path: str, text: str) -> None:
    if not text:
        return
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _resolve_agent_executable(output_path: str) -> Optional[Path]:
    explicit = os.environ.get("EDR_AGENT_EXECUTABLE", "").strip()
    if explicit:
        candidate = Path(explicit).expanduser().resolve()
        if not candidate.is_file():
            raise ConfigValidationError(f"EDR_AGENT_EXECUTABLE is not a file: {candidate}")
        return candidate

    output_dir = Path(output_path).expanduser().resolve().parent
    script_dir = Path(__file__).resolve().parent
    directories = [output_dir, script_dir, script_dir.parent, Path.cwd().resolve()]
    if sys.platform.lower().startswith("win"):
        program_files = os.environ.get("ProgramFiles", "").strip()
        if program_files:
            directories.extend(
                [Path(program_files) / "FDSecurity", Path(program_files) / "EDR Agent"]
            )
        names = ("FDSensor.exe", "edr_agent.exe")
    else:
        directories.append(Path("/usr/local/bin"))
        names = ("edr_agent", "FDSensor")
    seen = set()
    for directory in directories:
        for name in names:
            candidate = directory / name
            key = str(candidate)
            if key in seen:
                continue
            seen.add(key)
            if candidate.is_file():
                return candidate
    return None


def _validate_config_with_agent(agent_path: Path, config_path: Path) -> None:
    try:
        result = subprocess.run(
            [str(agent_path), "--config", str(config_path), "--config-test"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConfigValidationError(f"could not run Agent config parser: {exc}") from exc
    if result.returncode == 0:
        return
    raise ConfigValidationError(f"Agent rejected generated config (exit {result.returncode})")


def _secure_staged_file_windows(path: Path) -> None:
    import ctypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = ctypes.c_int
    set_security = advapi32.SetFileSecurityW
    set_security.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p]
    set_security.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    descriptor = ctypes.c_void_p()
    if not convert(
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)", 1, ctypes.byref(descriptor), None
    ):
        raise ConfigValidationError(
            f"could not create protected staged-config ACL (Windows error {ctypes.get_last_error()})"
        )
    try:
        security_information = 0x4 | 0x80000000
        if not set_security(str(path), security_information, descriptor):
            raise ConfigValidationError(
                f"could not protect staged config (Windows error {ctypes.get_last_error()})"
            )
    finally:
        kernel32.LocalFree(descriptor)


def _stage_validated_config(
    path: str, text: str, allow_missing_agent: bool = False
) -> tuple[Path, Path, Optional[Path]]:
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, staged_name = tempfile.mkstemp(prefix=f".{target.name}.config-test-", suffix=".tmp", dir=target.parent)
    staged = Path(staged_name)
    try:
        if os.name == "nt":
            _secure_staged_file_windows(staged)
        else:
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as config_file:
            fd = -1
            config_file.write(text)
            config_file.flush()
            os.fsync(config_file.fileno())

        agent_path = _resolve_agent_executable(str(target))
        if agent_path is None:
            if not allow_missing_agent:
                raise ConfigValidationError(
                    "Agent executable not found; place it beside agent.toml, set "
                    "EDR_AGENT_EXECUTABLE, or use --generate-only for a script-only bundle"
                )
            print(
                "warning: --generate-only wrote config without Agent parser validation",
                file=sys.stderr,
            )
        else:
            _validate_config_with_agent(agent_path, staged)
        return target, staged, agent_path
    except BaseException:
        # Windows cannot unlink this staging file while the CRT descriptor is
        # still open (for example when ACL setup or fdopen itself failed).
        if fd >= 0:
            os.close(fd)
            fd = -1
        try:
            staged.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def _replace_file_windows(target: Path, staged: Path, replace_file=None, get_last_error=None) -> None:
    # ReplaceFileW retains the existing destination's ACLs and metadata while
    # atomically swapping the parser-validated file, matching File.Replace in
    # the PowerShell installer.
    import ctypes

    backup_fd, backup_name = tempfile.mkstemp(
        prefix=f".{target.name}.replace-", suffix=".bak", dir=target.parent
    )
    os.close(backup_fd)
    os.unlink(backup_name)
    if replace_file is None:
        replace_file = ctypes.WinDLL("kernel32", use_last_error=True).ReplaceFileW
        replace_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        replace_file.restype = ctypes.c_int
    if get_last_error is None:
        get_last_error = ctypes.get_last_error
    replaced = replace_file(str(target), str(staged), backup_name, 0, None, None)
    if not replaced:
        error_code = int(get_last_error())
        backup = Path(backup_name)
        # ReplaceFileW error 1177 means the original may already have moved to
        # the backup while the replacement was not installed. Restore it before
        # the caller removes the staged candidate.
        if error_code == 1177 and not target.exists() and backup.exists():
            try:
                os.replace(backup, target)
            except OSError as rollback_error:
                raise ConfigValidationError(
                    f"ReplaceFileW failed with Windows error 1177 and original config "
                    f"recovery failed; backup retained at {backup}: {rollback_error}"
                ) from rollback_error
            raise ConfigValidationError(
                "ReplaceFileW failed with Windows error 1177; original config restored"
            )
        backup_note = f"; backup retained at {backup}" if backup.exists() else ""
        raise ConfigValidationError(
            f"ReplaceFileW failed with Windows error {error_code}{backup_note}"
        )
    try:
        Path(backup_name).unlink()
    except OSError as exc:
        print(f"warning: validated config backup remains at {backup_name}: {exc}", file=sys.stderr)


def _replace_staged_config(target: Path, staged: Path) -> None:
    if os.name == "nt" and target.exists():
        _replace_file_windows(target, staged)
        return
    if os.name != "nt" and target.exists():
        os.chmod(staged, target.stat().st_mode & 0o777)
    os.replace(staged, target)


def _write_validated_config(
    path: str, text: str, allow_missing_agent: bool = False
) -> Optional[Path]:
    target, staged, agent_path = _stage_validated_config(
        path, text, allow_missing_agent=allow_missing_agent
    )
    try:
        _replace_staged_config(target, staged)
        return agent_path
    finally:
        try:
            staged.unlink()
        except FileNotFoundError:
            pass


def _restore_certificate_files(snapshots) -> None:
    failures = []
    for path, previous in reversed(snapshots):
        try:
            if previous is None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            else:
                with path.open("wb") as certificate_file:
                    certificate_file.write(previous)
                    certificate_file.flush()
                    os.fsync(certificate_file.fileno())
        except OSError as exc:
            failures.append(f"{path}: {exc}")
    if failures:
        raise ConfigValidationError(
            "certificate file rollback failed: " + "; ".join(failures)
        )


def _install_enrollment_config(
    path: str,
    text: str,
    ca_path: str,
    ca_text: str,
    client_cert_path: str,
    client_cert_text: str,
    key_provider: str,
    allow_missing_agent: bool = False,
) -> Optional[Path]:
    target, staged, agent_path = _stage_validated_config(
        path, text, allow_missing_agent=allow_missing_agent
    )
    certificate_snapshots = []
    try:
        if ca_text or client_cert_text:
            if not (ca_text and client_cert_text):
                raise ConfigValidationError(
                    "enroll response returned an incomplete mTLS certificate bundle"
                )
            certificate_paths = (Path(ca_path).expanduser().resolve(), Path(client_cert_path).expanduser().resolve())
            certificate_snapshots = [
                (certificate_path, certificate_path.read_bytes() if certificate_path.exists() else None)
                for certificate_path in certificate_paths
            ]
            _write_pem(ca_path, ca_text)
            _write_pem(client_cert_path, client_cert_text)
            _accept_cng_cert(client_cert_path, key_provider)
        _replace_staged_config(target, staged)
        return agent_path
    except BaseException as install_error:
        try:
            _restore_certificate_files(certificate_snapshots)
        except ConfigValidationError as rollback_error:
            raise ConfigValidationError(
                f"installation failed and certificate rollback was incomplete: {rollback_error}"
            ) from install_error
        raise
    finally:
        try:
            staged.unlink()
        except FileNotFoundError:
            pass


def _redact_generated_toml(text: str) -> str:
    import re

    for key in ("rest_bearer_token", "secret"):
        text = re.sub(
            rf'(?m)^(\s*{key}\s*=\s*")(?:\\.|[^"\\])*(")',
            rf"\1<redacted>\2",
            text,
        )
    return text


def main() -> None:
    p = argparse.ArgumentParser(description="FDSecurity enroll -> agent.toml")
    p.add_argument(
        "-o",
        "--output",
        default=os.environ.get("EDR_OUTPUT", "agent.toml"),
        help="output agent.toml path",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="print TOML without writing agent.toml/issued certs; key and CSR generation still occurs",
    )
    p.add_argument(
        "--generate-only",
        action="store_true",
        help="allow a script-only bundle to write config when no Agent executable is available",
    )
    args = p.parse_args()

    api_base = os.environ.get("EDR_API_BASE", "").strip()
    token = os.environ.get("EDR_ENROLL_TOKEN", "").strip()
    if not api_base or not token:
        print("Set EDR_API_BASE and EDR_ENROLL_TOKEN", file=sys.stderr)
        sys.exit(2)

    av = _resolve_agent_version(args.output)
    print(f"Resolved agent_version={av}")
    ca_path, cert_path, key_path = _default_cert_paths()
    csr_path = _default_csr_path(key_path)
    key_provider = _normalize_key_provider()
    csr_pem = _ensure_csr(key_path, csr_path, key_provider)
    out = enroll(api_base, token, av, csr_pem)
    use_cert_paths = bool(
        out["ca_cert"]
        or out["client_cert"]
        or os.environ.get("EDR_CA_CERT")
        or os.environ.get("EDR_CLIENT_CERT")
        or os.environ.get("EDR_CLIENT_KEY")
    )
    effective_key_path = key_path if use_cert_paths and key_provider == "pem" else ""
    cert_store = r"LocalMachine\My" if key_provider in {"cng", "tpm"} else ""
    cert_thumbprint = _pem_thumbprint_sha1(out["client_cert"]) if out["client_cert"] else ""
    text = _emit_toml(
        out["server_addr"],
        out["endpoint_id"],
        out["tenant_id"],
        out["rest_base"],
        out.get("rest_bearer_token", ""),
        ca_path if use_cert_paths else "",
        cert_path if use_cert_paths else "",
        effective_key_path,
        key_provider,
        cert_store,
        cert_thumbprint,
        os.environ.get("EDR_PKCS11_MODULE", ""),
        os.environ.get("EDR_PKCS11_KEY_URI", ""),
        os.environ.get("EDR_TPM_KEY_URI", ""),
        out.get("request_signing_enabled", False),
        out.get("request_signing_key_id", ""),
        out.get("request_signing_secret", ""),
        str(Path(args.output).expanduser().resolve().parent),
    )
    if args.dry_run:
        print(_redact_generated_toml(text))
        return
    path = args.output
    try:
        validated_by = _install_enrollment_config(
            path,
            text,
            ca_path,
            out["ca_cert"],
            cert_path,
            out["client_cert"],
            key_provider,
            allow_missing_agent=args.generate_only,
        )
    except (ConfigValidationError, OSError) as exc:
        print(f"generated agent.toml was not installed: {exc}", file=sys.stderr)
        sys.exit(1)
    if validated_by is not None:
        print(f"Validated generated config with {validated_by}")
    print(
        f"Wrote {path} (endpoint_id={out['endpoint_id']} "
        f"tenant_id={out['tenant_id']} server.address={out['server_addr']})"
    )


if __name__ == "__main__":
    main()
