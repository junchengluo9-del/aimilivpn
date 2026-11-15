#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import select
import shlex
import shutil
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid

# Prefer IPv4 resolution to avoid slow AAAA DNS timeouts (e.g. in WSL),
# but fall back to system default (IPv6) if IPv4 resolution fails.
# This ensures pure-IPv6 VPS (with NAT64/clatd) can still function.
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        if isinstance(host, str) and ":" in host:
            return _orig_getaddrinfo(host, port, socket.AF_INET6, type, proto, flags)
        # Try IPv4 first for speed; fall back to system default (allows IPv6/NAT64)
        try:
            results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
            if results:
                return results
        except socket.gaierror:
            pass
        return _orig_getaddrinfo(host, port, 0, type, proto, flags)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

class DualStackHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        host, port = server_address
        if ":" in host or host == "":
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        
        try:
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        except OSError as e:
            if self.address_family == socket.AF_INET6:
                fallback_host = "0.0.0.0" if host in ("::", "") else "127.0.0.1"
                print(f"[警告] 绑定 Web 管理后台 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 {fallback_host} ...", flush=True)
                # 关闭第一次失败时可能已创建的 socket
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.address_family = socket.AF_INET
                super().__init__((fallback_host, port), RequestHandlerClass, bind_and_activate)
            else:
                raise e

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()

import vpn_utils
import proxy_server

def env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        print(f"[配置警告] 环境变量 {name}={raw!r} 不是有效整数，使用默认值 {default}", flush=True)
        value = default
    if min_value is not None and value < min_value:
        print(f"[配置警告] 环境变量 {name}={value} 小于允许值 {min_value}，使用默认值 {default}", flush=True)
        return default
    if max_value is not None and value > max_value:
        print(f"[配置警告] 环境变量 {name}={value} 大于允许值 {max_value}，使用默认值 {default}", flush=True)
        return default
    return value

def bounded_int(value: Any, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if min_value is not None and parsed < min_value:
        return default
    if max_value is not None and parsed > max_value:
        return default
    return parsed

API_URL = "https://www.vpngate.net/api/iphone/"
MIRROR_SOURCES = [
    "https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/pool/servers.json",
    "https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/data/vpngate.csv",
    "https://raw.githubusercontent.com/sinspired/VpngateAPI/main/servers.csv",
]
FETCH_INTERVAL_SECONDS = env_int("FETCH_INTERVAL_SECONDS", 1260, 1)
CHECK_INTERVAL_SECONDS = env_int("CHECK_INTERVAL_SECONDS", 1260, 1)
TARGET_VALID_NODES = env_int("TARGET_VALID_NODES", 3, 1)
MAX_SCAN_ROWS = env_int("MAX_SCAN_ROWS", 800, 1)
OPENVPN_TEST_TIMEOUT_SECONDS = env_int("OPENVPN_TEST_TIMEOUT_SECONDS", 35, 1)
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
LOCAL_PROXY_PORT = env_int("LOCAL_PROXY_PORT", 7928, 1, 65535)
UI_HOST = os.environ.get("UI_HOST", "::")
UI_PORT = env_int("UI_PORT", 8787, 1, 65535)
INVALID_BACKOFF_SECONDS = env_int("INVALID_BACKOFF_SECONDS", 30 * 60, 1)

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
UPSTREAM_PROXY_AUTH_FILE = DATA_DIR / "upstream_proxy_auth.txt"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"

lock = threading.RLock()
maintenance_lock = threading.Lock()
active_sessions: dict[str, float] = {}
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
is_connecting = True
last_active_ping_time = 0.0
last_active_latency = 0

last_collector_heartbeat = 0.0
last_checker_heartbeat = 0.0
last_pinger_heartbeat = 0.0
server_start_time = time.time()

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

def upstream_proxy_auth_file() -> str | None:
    username, password = vpn_utils.get_upstream_proxy_auth()
    if username is None:
        return None
    try:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        UPSTREAM_PROXY_AUTH_FILE.write_text(f"{username}\n{password or ''}\n", encoding="utf-8")
        try:
            UPSTREAM_PROXY_AUTH_FILE.chmod(0o600)
        except OSError:
            pass
        return str(UPSTREAM_PROXY_AUTH_FILE)
    except Exception as exc:
        print(f"[上游代理认证] 写入认证文件失败: {exc}", flush=True)
        return None

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

import hashlib
import random

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": UI_HOST,
            "port": UI_PORT,
            "proxy_port": LOCAL_PROXY_PORT,
            "routing_mode": "auto",
            "force_country": "",
            "routing_ip_type": "all",
            "connection_enabled": True,
            "fixed_node_id": "",
            "favorite_node_ids": [],
            "fav_fail_fallback": True
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                for key in ["host", "port", "proxy_port", "routing_mode", "force_country", "routing_ip_type", "connection_enabled", "fixed_node_id", "favorite_node_ids", "fav_fail_fallback"]:
                    if key not in data:
                        updated = True
            except Exception:
                pass
        
        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True
            
        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True

        normalized_port = bounded_int(config.get("port"), UI_PORT, 1, 65535)
        if normalized_port != config.get("port"):
            config["port"] = normalized_port
            updated = True

        normalized_proxy_port = bounded_int(config.get("proxy_port"), LOCAL_PROXY_PORT, 1024, 65535)
        if normalized_proxy_port == normalized_port:
            fallback_proxy_port = LOCAL_PROXY_PORT if LOCAL_PROXY_PORT != normalized_port else 7928
            if fallback_proxy_port == normalized_port:
                fallback_proxy_port = 7929
            normalized_proxy_port = fallback_proxy_port
        if normalized_proxy_port != config.get("proxy_port"):
            config["proxy_port"] = normalized_proxy_port
            updated = True
            
        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                auth_file.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
                
        return config

# 初始化时优先从 ui_auth.json 加载保存的代理出站端口和网页端口配置以覆盖环境变量
try:
    _init_cfg = load_ui_config()
    if "proxy_port" in _init_cfg:
        LOCAL_PROXY_PORT = bounded_int(_init_cfg["proxy_port"], LOCAL_PROXY_PORT, 1024, 65535)
    if "port" in _init_cfg:
        UI_PORT = bounded_int(_init_cfg["port"], UI_PORT, 1, 65535)
    if "host" in _init_cfg:
        UI_HOST = _init_cfg["host"]
except Exception:
    pass

def get_session_token(password: str, username: str = "admin") -> str:
    salt = "aimilivpn_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

_last_cleanup_time = 0.0

def cleanup_old_logs(logs_dir: Path) -> None:
    global _last_cleanup_time
    now = time.time()
    with lock:
        if now - _last_cleanup_time < 3600:
            return
        _last_cleanup_time = now
    try:
        three_days_sec = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= three_days_sec:
                        with lock:
                            path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        with lock:
                            path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with lock:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)

def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)

def read_nodes() -> list[dict[str, Any]]:
    raw = read_json(NODES_FILE, [])
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    state.pop("password", None)
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state.setdefault("api_url", API_URL)
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    _proxy_display = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
    state["local_proxy"] = f"http://{_proxy_display}:{LOCAL_PROXY_PORT}"
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("blacklisted_nodes", 0)
    
    # Pre-populate settings inputs in UI
    ui_cfg = load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8787)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    state["password_set"] = bool(ui_cfg.get("password"))
    state["proxy_port"] = ui_cfg.get("proxy_port", 7928)
    state["routing_mode"] = ui_cfg.get("routing_mode", "auto")
    state["force_country"] = ui_cfg.get("force_country", "")
    state["routing_ip_type"] = ui_cfg.get("routing_ip_type", "all")
    state["connection_enabled"] = ui_cfg.get("connection_enabled", True)
    state["fixed_node_id"] = ui_cfg.get("fixed_node_id", "")
    state["favorite_node_ids"] = ui_cfg.get("favorite_node_ids", [])
    state["fav_fail_fallback"] = ui_cfg.get("fav_fail_fallback", True)
    
    return state

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"

def clear_active_connection_state(message: str) -> None:
    global active_openvpn_process, active_openvpn_node_id
    stop_process(active_openvpn_process)
    active_openvpn_process = None
    active_openvpn_node_id = ""
    with lock:
        nodes = read_nodes()
        for item in nodes:
            item["active"] = False
        write_json(NODES_FILE, nodes)
    set_state(
        active_openvpn_node_id="",
        is_connecting=False,
        active_node_latency="无活动连接",
        last_check_message=message,
    )

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def proxy_basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"

def recv_exact_from_socket(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Unexpected EOF while reading proxy response")
        data += chunk
    return data

def read_http_response_head(sock: socket.socket, limit: int = 65536) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise RuntimeError("Proxy response header too large")
    if b"\r\n\r\n" not in data:
        raise RuntimeError("Incomplete HTTP proxy response header")
    return data

def socks5_address_bytes(host: str) -> tuple[int, bytes]:
    try:
        return 1, socket.inet_aton(host)
    except OSError:
        pass
    try:
        return 4, socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        pass
    host_bytes = host.encode("idna")
    if len(host_bytes) > 255:
        raise RuntimeError("SOCKS5 target host name is too long")
    return 3, bytes([len(host_bytes)]) + host_bytes

def read_socks5_connect_reply(sock: socket.socket) -> None:
    header = recv_exact_from_socket(sock, 4)
    if header[0] != 5:
        raise RuntimeError("Invalid SOCKS5 reply version")
    atyp = header[3]
    if atyp == 1:
        recv_exact_from_socket(sock, 4)
    elif atyp == 3:
        domain_len = recv_exact_from_socket(sock, 1)[0]
        recv_exact_from_socket(sock, domain_len)
    elif atyp == 4:
        recv_exact_from_socket(sock, 16)
    else:
        raise RuntimeError(f"Invalid SOCKS5 reply address type: {atyp}")
    recv_exact_from_socket(sock, 2)
    if header[1] != 0:
        raise RuntimeError(f"SOCKS5 connection request rejected, code={header[1]}")

def format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"

def fetch_api_text_via_proxy(url: str, ptype: str, phost: str, pport: int, use_ssl_verify: bool = True) -> str:
    import socket
    import ssl
    import urllib.parse

    parsed = urllib.parse.urlsplit(url)
    domain = parsed.hostname or "www.vpngate.net"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    is_ipv6 = ":" in phost
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(12)
        s.connect((phost, pport))
        proxy_user, proxy_pass = vpn_utils.get_upstream_proxy_auth()
        if ptype == "socks":
            # SOCKS5 Handshake
            if proxy_user is not None:
                s.sendall(b"\x05\x02\x00\x02")
            else:
                s.sendall(b"\x05\x01\x00")
            resp = recv_exact_from_socket(s, 2)
            if len(resp) < 2 or resp[0] != 5:
                raise RuntimeError("SOCKS5 authentication failed or unsupported")
            if resp[1] == 2:
                if proxy_user is None:
                    raise RuntimeError("SOCKS5 proxy requires username/password authentication")
                user_bytes = proxy_user.encode("utf-8")
                pass_bytes = (proxy_pass or "").encode("utf-8")
                if len(user_bytes) > 255 or len(pass_bytes) > 255:
                    raise RuntimeError("SOCKS5 proxy credentials are too long")
                s.sendall(b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes)
                auth_resp = recv_exact_from_socket(s, 2)
                if len(auth_resp) < 2 or auth_resp[1] != 0:
                    raise RuntimeError("SOCKS5 username/password authentication failed")
            elif resp[1] != 0:
                raise RuntimeError("SOCKS5 authentication method unsupported")
            # SOCKS5 Connect
            atyp, addr_bytes = socks5_address_bytes(domain)
            req = b"\x05\x01\x00" + bytes([atyp]) + addr_bytes + port.to_bytes(2, 'big')
            s.sendall(req)
            read_socks5_connect_reply(s)
            # If HTTPS, wrap socket with SSL
            if is_https:
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
        else: # http proxy
            if is_https:
                # HTTP CONNECT tunnel
                authority = format_host_port(domain, port)
                auth_header = proxy_basic_auth_header(proxy_user, proxy_pass or "") if proxy_user is not None else ""
                req_str = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n{auth_header}Proxy-Connection: Keep-Alive\r\n\r\n"
                s.sendall(req_str.encode('ascii'))
                resp = read_http_response_head(s)
                status_line = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                status_parts = status_line.split()
                status_code = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 0
                if status_code != 200:
                    raise RuntimeError(f"HTTP CONNECT tunnel failed: {status_line}")
                # Wrap socket with SSL
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
            else:
                # Direct HTTP request through proxy: request URI must be absolute
                pass

        # Send HTTP GET request
        if ptype == "http" and not is_https:
            request_uri = url
        else:
            request_uri = path
            
        req_headers = (
            f"GET {request_uri} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n"
            f"Accept: text/plain,*/*\r\n"
            f"{proxy_basic_auth_header(proxy_user, proxy_pass or '') if ptype == 'http' and not is_https and proxy_user is not None else ''}"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(req_headers.encode('utf-8'))

        # Read response
        response_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if len(response_data) > 10 * 1024 * 1024: # max 10MB safety guard
                break
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # Parse HTTP response
    header_end = response_data.find(b"\r\n\r\n")
    if header_end == -1:
        raise RuntimeError("Invalid HTTP response format")
    
    headers_part = response_data[:header_end].decode('utf-8', errors='replace')
    body_part = response_data[header_end+4:]

    # Check for HTTP status code
    lines = headers_part.splitlines()
    if not lines:
        raise RuntimeError("Empty response headers")
    status_line = lines[0]
    status_parts = status_line.split()
    if len(status_parts) >= 2:
        try:
            status_code = int(status_parts[1])
            if status_code != 200:
                raise RuntimeError(f"HTTP Server returned status {status_code}: {status_line}")
        except ValueError:
            pass

    # Handle chunked transfer encoding
    is_chunked = False
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() == "transfer-encoding" and "chunked" in v.lower():
                is_chunked = True
                break

    if is_chunked:
        decoded = b""
        idx = 0
        while idx < len(body_part):
            c_end = body_part.find(b"\r\n", idx)
            if c_end == -1:
                break
            chunk_size_str = body_part[idx:c_end].split(b";")[0].strip()
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            idx = c_end + 2
            decoded += body_part[idx : idx + chunk_size]
            idx += chunk_size + 2
        body_part = decoded

    return body_part.decode('utf-8', errors='replace')

def fetch_api_text(url: str | None = None, use_ssl_verify: bool = True) -> str:
    if url is None:
        url = API_URL
    
    ptype, phost, pport = vpn_utils.get_upstream_proxy()
    if ptype and phost and pport:
        try:
            print(f"[fetch_api_text] 监测到上游代理 ({ptype}://{phost}:{pport})，尝试通过代理获取 API...", flush=True)
            return fetch_api_text_via_proxy(url, ptype, phost, pport, use_ssl_verify)
        except Exception as e:
            print(f"[fetch_api_text] 通过代理获取 API 失败: {e}，尝试使用直连/默认系统代理...", flush=True)
            log_to_json("WARNING", "Main", f"使用代理 {ptype}://{phost}:{pport} 获取 API 失败: {e}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 vpngate-openvpn-manager/2.0",
            "Accept": "text/plain,*/*",
        },
    )
    if url.startswith("https://") and not use_ssl_verify:
        import ssl
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=12, context=ctx) as response:
            return response.read().decode("utf-8", errors="replace")
    else:
        with urllib.request.urlopen(request, timeout=12) as response:
            return response.read().decode("utf-8", errors="replace")

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")

def load_blacklist() -> dict[str, dict[str, Any]]:
    now = time.time()
    raw = read_json(BLACKLIST_FILE, {})
    if not isinstance(raw, dict):
        return {}
    cleaned: dict[str, dict[str, Any]] = {}
    changed = False
    for key, entry in raw.items():
        if not isinstance(entry, dict):
            changed = True
            continue
        until = float(entry.get("until", 0) or 0)
        if until and until > now:
            cleaned[str(key)] = entry
        else:
            changed = True
    if changed:
        write_json(BLACKLIST_FILE, cleaned)
    return cleaned

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    node_id = str(node.get("id") or "").strip()
    if not node_id:
        return
    blacklist = load_blacklist()
    now = time.time()
    blacklist[node_id] = {
        "id": node_id,
        "ip": node.get("ip") or node.get("remote_host") or "",
        "country": node.get("country", ""),
        "reason": message,
        "marked_at": now,
        "until": now + INVALID_BACKOFF_SECONDS,
    }
    write_json(BLACKLIST_FILE, blacklist)

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    
    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
    }

def fetch_candidates() -> list[dict[str, Any]]:
    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_ips = set()
    
    # 检查本地是否有节点缓存，以确定最大重试尝试次数
    has_cache = len(cached_nodes()) > 0
    max_attempts = 1 if has_cache else 2
    
    # 尝试 URLs 队列: 官方 API + 镜像 CSV
    attempts_targets = [
        (API_URL, True),
        (API_URL, False),
    ]
    if API_URL.startswith("https://"):
        attempts_targets.append((API_URL.replace("https://", "http://"), True))
    # 追加镜像源
    for src in MIRROR_SOURCES:
        if src.endswith(".csv"):
            attempts_targets.append((src, False))
        
    log_to_json("INFO", "Main", "开始拉取官方 API 节点列表...")
    
    last_err = None
    for url, verify_ssl in attempts_targets:
        for i in range(max_attempts):
            if i > 0:
                time.sleep(1.5)
            try:
                msg = f"尝试拉取 {url} (SSL验证: {verify_ssl}, 第 {i+1} 次尝试)..."
                print(f"[fetch_candidates] {msg}", flush=True)
                log_to_json("INFO", "Main", msg)
                api_text = fetch_api_text(url, verify_ssl)
                rows = parse_vpngate_rows(api_text)
                for row in rows[:MAX_SCAN_ROWS]:
                    ip = row.get("IP", "")
                    if not ip or ip in seen_ips:
                        continue
                    encoded = row.get("OpenVPN_ConfigData_Base64", "")
                    if not encoded:
                        continue
                    try:
                        config_text = decode_config(encoded)
                        node = row_to_node(row, config_text)
                    except Exception as row_exc:
                        print(f"[fetch_candidates] 跳过损坏的节点配置记录: {row_exc}", flush=True)
                        log_to_json("WARNING", "Main", f"跳过损坏的节点配置记录: {row_exc}")
                        continue
                    entry = blacklist.get(node["id"])
                    if entry and float(entry.get("until", 0) or 0) > time.time():
                        continue
                    candidates.append(node)
                    seen_ips.add(ip)
            except Exception as e:
                last_err = e
                print(f"[fetch_candidates] 拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}", flush=True)
                log_to_json("WARNING", "Main", f"拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}")
            
    if not candidates:
        err_code, diag_msg = vpn_utils.diagnose_api_failure(API_URL)
        full_err_msg = f"获取官方 API 节点最终失败: {last_err} | 诊断结果: {diag_msg}"
        print(f"[错误代码 {err_code}] {full_err_msg}", flush=True)
        log_to_json("ERROR", "Main", f"[错误代码 {err_code}] {full_err_msg}")
        set_state(
            last_fetch_status="error",
            last_fetch_error_code=err_code,
            last_fetch_message=diag_msg
        )
        if last_err:
            raise RuntimeError(diag_msg) from last_err
        else:
            raise RuntimeError(diag_msg)
                
    set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok",
        last_fetch_message=f"Fetched {len(candidates)} unique candidates across multiple attempts.",
        blacklisted_nodes=len(blacklist),
    )
    log_to_json("INFO", "Main", f"成功获取官方 API 节点，共 {len(candidates)} 个候选节点")
    return candidates

def cached_nodes() -> list[dict[str, Any]]:
    return read_nodes()

_openvpn_version = None

def split_openvpn_command() -> list[str]:
    try:
        return shlex.split(OPENVPN_CMD, posix=(os.name != "nt")) or ["openvpn"]
    except ValueError as exc:
        raise RuntimeError(f"OPENVPN_CMD 配置无法解析: {exc}") from exc

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = split_openvpn_command()
        res = subprocess.run(cmd + ["--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0") -> list[str]:
    command = split_openvpn_command()
    command.extend(
        [
            "--config",
            config_file,
            "--dev",
            dev,
            "--dev-type",
            "tun",
            "--pull-filter",
            "ignore",
            "route-ipv6",
            "--pull-filter",
            "ignore",
            "ifconfig-ipv6",
            "--route-delay",
            "2",
            "--connect-retry-max",
            "1",
            "--connect-timeout",
            "15",
            "--auth-user-pass",
            str(AUTH_FILE),
            "--auth-nocache",
        ]
    )
    
    version = get_openvpn_version()
    if version >= 2.5:
        command.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else:
        command.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])

    command.extend(["--verb", "3"])
    
    if os.path.exists("/etc/ssl/certs"):
        command.extend(["--capath", "/etc/ssl/certs"])
    
    try:
        content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        if vpn_utils.is_config_tcp(content):
            ptype, host, port = vpn_utils.get_upstream_proxy()
            auth_file = upstream_proxy_auth_file()
            if ptype == "socks" and host and port:
                command.extend(["--socks-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
            elif ptype == "http" and host and port:
                command.extend(["--http-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
    except Exception:
        pass
        
    if route_nopull:
        command.append("--route-nopull")
    return command

def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()

def kill_existing_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        own_markers = [
            str(DATA_DIR),
            str(CONFIG_DIR),
            str(AUTH_FILE),
            str(UPSTREAM_PROXY_AUTH_FILE),
        ]
        killed_pids: list[int] = []
        proc_root = Path("/proc")
        if not proc_root.exists():
            return
        for proc_dir in proc_root.iterdir():
            if not proc_dir.name.isdigit():
                continue
            pid = int(proc_dir.name)
            if pid == os.getpid():
                continue
            try:
                raw = (proc_dir / "cmdline").read_bytes()
            except OSError:
                continue
            if not raw:
                continue
            args = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
            if not args:
                continue
            cmdline = " ".join(args)
            executable = Path(args[0]).name.lower()
            if "openvpn" not in executable and "openvpn" not in cmdline.lower():
                continue
            if any(marker and marker in cmdline for marker in own_markers):
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed_pids.append(pid)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    print(f"[Cleanup] No permission to terminate OpenVPN PID {pid}", flush=True)
        if killed_pids:
            time.sleep(0.5)
            for pid in killed_pids:
                try:
                    raw = (proc_root / str(pid) / "cmdline").read_bytes()
                    cmdline = " ".join(part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part)
                    if any(marker and marker in cmdline for marker in own_markers):
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except (OSError, PermissionError):
                    pass
            print(f"[Cleanup] Terminated AimiliVPN OpenVPN processes: {killed_pids}", flush=True)
    except Exception as e:
        print(f"[Cleanup Error] Failed to kill existing OpenVPN processes: {e}", flush=True)

def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def run_openvpn_until_ready(config_file: str, keep_alive: bool, route_nopull: bool, timeout: int | None = None, dev: str = "tun0") -> tuple[bool, str, subprocess.Popen[str] | None]:
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "[错误代码 2001] [ERR_OVPN_CMD_NOT_FOUND] 未找到 openvpn 命令。原因: 系统未安装 openvpn，或 PATH 环境变量不正确。", None
    except OSError as exc:
        return False, f"[错误代码 2002] [ERR_OVPN_START_FAILED] openvpn 启动失败: {exc}。原因: 系统权限不足或配置冲突。", None

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]
    openvpn_logs: list[str] = []

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            line_str = line.rstrip()
            if not startup_done[0]:
                openvpn_logs.append(line_str)
                lines.put(line_str)
            else:
                if keep_alive:
                    print(f"[OpenVPN] {line_str}", flush=True)
                    level = "INFO"
                    line_lower = line_str.lower()
                    if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
                        level = "ERROR"
                    elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
                        level = "WARNING"
                    log_to_json(level, "VPN", f"[OpenVPN] {line_str}")
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-50:]
            if keep_alive:
                print(f"[OpenVPN] {line}", flush=True)
        lower = line.lower()
        if keep_alive:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            ok = True
            message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."

    # Bulk write accumulated startup logs
    for line_str in openvpn_logs:
        level = "INFO"
        line_lower = line_str.lower()
        if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
            level = "ERROR"
        elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
            level = "WARNING"
        log_to_json(level, "VPN", f"[OpenVPN] {line_str}")

    if not ok:
        err_code, diag_msg = vpn_utils.diagnose_openvpn_failure(tail)
        message = f"[错误代码 {err_code}] {diag_msg} (原始日志尾部: {tail[-1][-100:] if tail else '无'})"
    startup_done[0] = True
    if not keep_alive or not ok:
        stop_process(process)
        process = None
    return ok, message, process


def setup_policy_routing(interface: str = "tun0") -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    
    success = False
    for attempt in range(1, 4):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", "100"], check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", "100"], check=True, timeout=2)
            # 配置反向路径过滤 rp_filter 为 loose 模式 (2)，防止回包被内核静默丢弃
            for proc_path in ["all", "default", interface]:
                try:
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{proc_path}.rp_filter=2"], capture_output=True, timeout=2)
                except Exception:
                    pass
            print(f"[policy_routing] Enabled policy routing for interface {interface} (attempt {attempt} success)", flush=True)
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)
            
    if not success:
        print("[路由配置失败] [错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由，这可能会导致通过 VPN 接口的出站路由无法正常解析。请检查系统是否支持策略路由、iproute2 工具是否完整，以及是否具有 root 权限。", flush=True)
        log_to_json("ERROR", "Routing", "[错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由")

def cleanup_policy_routing() -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
        print("[policy_routing] Cleared policy routing table 100", flush=True)
    except Exception:
        pass

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    with lock:
        cleanup_policy_routing()
        config_to_delete = None
        if active_openvpn_node_id:
            nodes = read_nodes()
            node = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None)
            if node:
                config_to_delete = node.get("config_file")
                
        stop_process(active_openvpn_process)
        active_openvpn_process = None
        active_openvpn_node_id = ""
        kill_existing_openvpn_processes()
        
        if config_to_delete:
            try:
                path = Path(config_to_delete)
                if path.exists():
                    path.unlink()
            except Exception:
                pass

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    available_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "available" or n.get("active")],
        key=lambda n: (
            0 if n.get("ip_type") in ("residential", "mobile") else 1,
            parse_int(n.get("latency_ms")) or 999999,
            -parse_int(n.get("score"))
        )
    )
    untested_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "not_checked" and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), parse_int(n.get("ping")))
    )
    unavailable_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "unavailable" and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), -float(n.get("probed_at", 0)))
    )
    return available_nodes + untested_nodes + unavailable_nodes

active_test_indexes = set()
test_indexes_lock = threading.Lock()

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        raise RuntimeError("没有可用的 OpenVPN 测试网卡编号，请稍后重试")

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def test_config_path(node_id: str) -> Path:
    safe_id = safe_name(node_id)
    return CONFIG_DIR / f".test_{safe_id}_{uuid.uuid4().hex}.ovpn"

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        config_text = node.get("config_text") or ""
        h = str(node.get("remote_host") or node.get("ip"))
        p = parse_int(node.get("remote_port"))
        fallback_ping = parse_int(node.get("ping"))

    temp_path = test_config_path(node_id)
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(config_text, encoding="utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to write temp config file: {e}")

    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
    
    idx = None
    try:
        idx = get_free_test_index()
        ok, message, _ = run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=8, dev=f"tun{idx}")
    finally:
        if idx is not None:
            release_test_index(idx)
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

    temp_node = {
        "id": node_id,
        "ip": h,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
    }
    if ok:
        vpn_utils.enrich_ip_info([temp_node])

    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            node["probed_at"] = time.time()
            if ok:
                node["owner"] = temp_node["owner"]
                node["asn"] = temp_node["asn"]
                node["as_name"] = temp_node["as_name"]
                node["location"] = temp_node["location"]
                node["ip_type"] = temp_node["ip_type"]
                node["quality"] = temp_node["quality"]
            
            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def test_multiple_nodes(node_ids: list[str]) -> list[dict[str, Any]]:
    with lock:
        nodes = read_nodes()
        to_test = [n for n in nodes if n.get("id") in node_ids]
        
    def test_worker(args: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        idx, n_info = args
        node_id = n_info["id"]
        config_text = n_info.get("config_text") or ""
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = parse_int(n_info.get("remote_port"))
        fallback_ping = parse_int(n_info.get("ping"))
        
        temp_path = test_config_path(node_id)
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception as e:
            return {
                "id": node_id,
                "latency_ms": 0,
                "probe_status": "unavailable",
                "probe_message": f"Failed to write configuration: {e}",
                "probed_at": time.time(),
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
            }
            
        latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
        tun_idx = None
        try:
            tun_idx = get_free_test_index()
            dev_name = f"tun{tun_idx}"
            ok, message, _ = run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=8, dev=dev_name)
        finally:
            if tun_idx is not None:
                release_test_index(tun_idx)
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass
            
        temp_node = {
            "id": node_id,
            "ip": n_info.get("ip") or h,
            "remote_host": h,
            "remote_port": p,
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
        }
        return temp_node

    updated_nodes_map = {}
    max_workers = min(20, max(1, len(to_test)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_worker, (idx, n)): n["id"] for idx, n in enumerate(to_test)}
        for future in concurrent.futures.as_completed(futures):
            nid = futures[future]
            try:
                res = future.result()
                updated_nodes_map[nid] = res
            except Exception as e:
                updated_nodes_map[nid] = {
                    "id": nid,
                    "probe_status": "unavailable",
                    "probe_message": f"Test exception: {e}",
                    "latency_ms": 0
                }
                
    # 批量查询并丰富可用节点的地理及 ISP 信息，防止并发时被定位 API 接口限流
    successful_nodes = [res for res in updated_nodes_map.values() if res.get("probe_status") == "available"]
    if successful_nodes:
        try:
            vpn_utils.enrich_ip_info(successful_nodes)
        except Exception as ee:
            print(f"[test_multiple_nodes] 批量富化 IP 失败: {ee}", flush=True)

    with lock:
        current_nodes = read_nodes()
        for n in current_nodes:
            nid = n.get("id")
            if nid in updated_nodes_map:
                n.update(updated_nodes_map[nid])
        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)
        
    return list(updated_nodes_map.values())

def auto_switch_node(attempt: int = 0) -> None:
    if attempt >= 3:
        print("[自动切换] 连续切换失败已达 3 次，停止切换以防止主线程死锁，将在后台重新加载节点...", flush=True)
        return
        
    ui_cfg = load_ui_config()
    connection_enabled = ui_cfg.get("connection_enabled", True)
    if not connection_enabled:
        print("[自动切换] 连接已禁用，不进行自动切换。", flush=True)
        return

    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = ui_cfg.get("force_country", "")

    if routing_mode == "fixed_ip":
        print("[自动切换] 当前处于固定 IP 模式，不进行自动连接或切换。", flush=True)
        return

    # Find the next best available node
    with lock:
        nodes = read_nodes()
        candidates = [
            n for n in nodes 
            if n.get("probe_status") == "available" 
            and not n.get("active")
        ]
        
        if routing_mode == "fixed_region" and target_country:
            candidates = [
                n for n in candidates 
                if n.get("country") == target_country 
                or vpn_utils.COUNTRY_TRANSLATIONS.get(n.get("country", ""), n.get("country", "")) == target_country
            ]
        if routing_mode == "favorites":
            fav_ids = set(ui_cfg.get("favorite_node_ids", []))
            fav_candidates = [n for n in candidates if n.get("id") in fav_ids]
            if fav_candidates:
                candidates = fav_candidates
            else:
                fav_fail_fallback = ui_cfg.get("fav_fail_fallback", True)
                if not fav_fail_fallback:
                    candidates = []
            
        # Apply routing_ip_type filter
        routing_ip_type = ui_cfg.get("routing_ip_type", "all")
        if routing_ip_type == "residential":
            candidates = [n for n in candidates if n.get("ip_type") in ("residential", "mobile")]
        elif routing_ip_type == "hosting":
            candidates = [n for n in candidates if n.get("ip_type") == "hosting"]
            
        candidates.sort(key=lambda n: (parse_int(n.get("latency_ms")) or 999999, -parse_int(n.get("score"))))
        
    if candidates:
        next_node = candidates[0]
        msg = f"当前连接已失效或代理连通性检测失败，正在自动切换至最佳备用节点: {next_node['id']}"
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        try:
            connect_node(next_node["id"])
        except Exception as e:
            err_msg = f"切换到备用节点 {next_node['id']} 失败: {e}，将尝试下一个..."
            print(f"[自动切换] {err_msg}", flush=True)
            log_to_json("WARNING", "VPN", err_msg)
            auto_switch_node(attempt + 1)
    else:
        msg = "没有可用的备选节点，将自动断开并清理当前连接状态，同时在后台异步获取新节点..."
        if routing_mode == "fixed_region" and target_country:
            msg = f"没有可用的【{target_country}】备选节点，已断开连接，将在后台持续尝试获取新节点..."
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("WARNING", "VPN", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(active_openvpn_node_id="", last_check_message=msg)
        
        def bg_fetch_and_switch():
            try:
                maintain_valid_nodes(force=False)
                auto_switch_node()
            except Exception as e:
                print(f"[自动切换后台补齐] 获取并测试节点失败: {e}", flush=True)
        
        threading.Thread(target=bg_fetch_and_switch, daemon=True).start()

def connect_node(node_id: str) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    node_id = str(node_id or "").strip()
    if not node_id:
        raise ValueError("Node id is required")
    stopped_existing = False
    with lock:
        if is_connecting:
            print("[连接] 正在建立其他连接中，跳过此请求", flush=True)
            raise RuntimeError("当前已有连接或节点检测任务正在运行，请稍后再试")
        is_connecting = True
        set_state(is_connecting=True, active_node_latency="正在连接", last_check_message=f"正在初始化连接配置: {node_id}")
        
    try:
        log_to_json("INFO", "VPN", f"开始连接节点: {node_id}")

        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        
        ui_cfg = load_ui_config()
        ui_cfg["connection_enabled"] = True
        if ui_cfg.get("routing_mode") == "fixed_ip":
            ui_cfg["fixed_node_id"] = node_id
        auth_file = DATA_DIR / "ui_auth.json"
        with lock:
            DATA_DIR.mkdir(exist_ok=True, parents=True)
            auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        
        set_state(active_node_latency="清理连接", last_check_message="正在关闭与清理旧的 VPN 连接及网卡...")
        stop_active_openvpn()
        stopped_existing = True

        set_state(active_node_latency="写入配置", last_check_message="正在写入 OpenVPN 节点配置文件...")
        config_path = Path(node["config_file"])
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(node.get("config_text") or "", encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}")

        set_state(active_node_latency="启动核心", last_check_message="正在启动 OpenVPN Core 核心服务并建立连接...")
        ok, message, process = run_openvpn_until_ready(str(node["config_file"]), keep_alive=True, route_nopull=True)
        if not ok or process is None:
            try:
                if config_path.exists():
                    config_path.unlink()
            except Exception:
                pass
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
            log_to_json("ERROR", "VPN", f"连接节点 {node_id} 失败: {message}")
            print(f"[连接核心失败] 无法与 VPN 节点 {node_id} 建立隧道连接！详情: {message}", flush=True)
            set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="无活动连接", last_check_message=f"连接失败: {message}")
            with lock:
                active_openvpn_node_id = ""
            raise RuntimeError(message)
            
        with lock:
            active_openvpn_process = process
            active_openvpn_node_id = node_id
        
        set_state(active_node_latency="配置路由", last_check_message="正在配置策略路由规则与流量转发...")
        setup_policy_routing("tun0")
        
        global last_active_ping_time, last_active_latency
        last_active_ping_time = time.time()
        last_active_latency = 0
        
        set_state(active_node_latency="测试延迟", last_check_message="正在直连测试代理出口延迟与可用性...")
        try:
            ip = node.get("ip") or node.get("remote_host")
            port = parse_int(node.get("remote_port"))
            fallback = parse_int(node.get("ping"))
            latency = vpn_utils.ping_latency_ms(ip, port, fallback)
            if latency > 0:
                last_active_latency = latency
        except Exception:
            pass
            
        for item in nodes:
            item["active"] = item.get("id") == node_id
            if item["active"]:
                _ph = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
                item["probe_message"] = f"Active node. HTTP proxy: http://{_ph}:{LOCAL_PROXY_PORT}"
        write_json(NODES_FILE, nodes)
        
        set_state(last_check_message="正在测试本地代理出站联通性与出口 IP...")
        res = check_proxy_health()
        if res["ok"]:
            set_state(
                proxy_ok=True,
                proxy_ip=res["ip"],
                proxy_latency_ms=res["latency_ms"],
                proxy_error=""
            )
        else:
            set_state(
                proxy_ok=False,
                proxy_ip="-",
                proxy_latency_ms=0,
                proxy_error=res.get("error", "未知错误")
            )
            
        latency_str = f"{last_active_latency} ms" if last_active_latency > 0 else "检测超时"
        set_state(active_openvpn_node_id=node_id, is_connecting=False, last_check_message=f"Connected {node_id}", active_node_latency=latency_str)
        log_to_json("INFO", "VPN", f"节点 {node_id} 连接成功，出口网卡 tun0 已启用")
        return f"Connected {node_id}"
    except Exception as exc:
        if stopped_existing or (active_openvpn_node_id == node_id and not active_openvpn_running()):
            clear_active_connection_state(f"连接失败: {exc}")
        else:
            set_state(is_connecting=False, last_check_message=f"连接失败: {exc}")
        raise
    finally:
        with lock:
            is_connecting = False

def maintain_valid_nodes(force: bool = False) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    ensure_dirs()
    if not maintenance_lock.acquire(blocking=False):
        msg = "节点维护任务正在运行，请稍后再试"
        set_state(last_check_message=msg)
        return msg
    is_connecting = True
    try:
        if force:
            with lock:
                stop_active_openvpn()
        elif not active_openvpn_running():
            ui_cfg = load_ui_config()
            routing_mode = ui_cfg.get("routing_mode", "auto")
            connection_enabled = ui_cfg.get("connection_enabled", True)
            if connection_enabled:
                if routing_mode == "fixed_ip":
                    target_id = active_openvpn_node_id or ui_cfg.get("fixed_node_id", "")
                    if target_id:
                        nodes = read_nodes()
                        if any(n.get("id") == target_id for n in nodes):
                            print(f"[维护线程] 检测到固定 IP 模式下 OpenVPN 未运行，正在重新拉起同一节点: {target_id}", flush=True)
                            is_connecting = False
                            try:
                                connect_node(target_id)
                            except Exception as e:
                                print(f"[维护线程] 重新拉起固定节点 {target_id} 失败: {e}", flush=True)
                            is_connecting = True
                else:
                    has_active_id = False
                    with lock:
                        if active_openvpn_node_id:
                            has_active_id = True
                            stop_active_openvpn()
                    if has_active_id:
                        print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                        is_connecting = False
                        auto_switch_node()
                        is_connecting = True

        try:
            set_state(is_connecting=True, last_check_message="正在拉取最新的免费 VPN 节点列表...")
            candidates = fetch_candidates()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            diag_msg = str(exc)
            if not any(token in diag_msg for token in ["[ERR_", "错误代码"]):
                err_code, raw_diag = vpn_utils.diagnose_api_failure(API_URL)
                diag_msg = f"[错误代码 {err_code}] 获取节点失败: {exc} | 诊断结果: {raw_diag}"
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=diag_msg)
            candidates = []

        if not candidates:
            return "没有拉取到新节点"

        with lock:
            active_node = None
            if active_openvpn_node_id:
                current_nodes = read_nodes()
                active_node = next((n for n in current_nodes if n.get("id") == active_openvpn_node_id), None)
                
            merged: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            
            if active_node:
                merged.append(active_node)
                seen_ids.add(active_node["id"])
                
            for cand in candidates:
                if cand["id"] not in seen_ids:
                    merged.append(cand)
                    seen_ids.add(cand["id"])
                    
            if len(merged) > 1000:
                merged = merged[:1000]
                
            for n in merged:
                config_path = Path(n["config_file"])
                if not config_path.exists():
                    try:
                        config_path.write_text(n["config_text"], encoding="utf-8")
                    except Exception:
                        pass
                        
            write_json(NODES_FILE, merged)

        # Test all non-active nodes from the list
        with lock:
            current_nodes = read_nodes()
            to_test = [n for n in current_nodes if not n.get("active")]
            to_test_ids = [n["id"] for n in to_test]
            
        msg = f"开始对列表中所有候选节点进行周期连通性与延迟测试，待检测节点共 {len(to_test_ids)} 个"
        print(f"[周期检测] {msg}", flush=True)
        log_to_json("INFO", "Main", msg)
        
        set_state(is_connecting=True, last_check_message="正在并发检测所有节点可用性...")
        test_multiple_nodes(to_test_ids)
        is_connecting = False
        
        with lock:
            merged = read_nodes()
            
            # Identify available, unavailable, and active nodes
            available_nodes = [n["id"] for n in merged if n.get("probe_status") == "available"]
            unavailable_nodes = [n["id"] for n in merged if n.get("probe_status") == "unavailable"]
            active_node = next((n["id"] for n in merged if n.get("active")), "无")
            
            status_report = (
                f"周期节点检测完成。实时同步状态: 获取到候选节点共 {len(merged)} 个。 "
                f"其中【可用节点】{len(available_nodes)} 个: {available_nodes[:15]}...; "
                f"【不可用节点】{len(unavailable_nodes)} 个; "
                f"当前【正在正常运行的活动连接节点】为: {active_node}。"
            )
            print(f"[周期检测] {status_report}", flush=True)
            log_to_json("INFO", "Main", status_report)
            
            if active_node != "无" and not active_openvpn_running():
                warn_msg = f"[诊断警告] 活动节点 {active_node} 被标记为活动状态，但 OpenVPN 进程实际并未正常运行！"
                print(warn_msg, flush=True)
                log_to_json("WARNING", "Main", warn_msg)
            
            if not active_openvpn_running():
                ui_cfg = load_ui_config()
                connection_enabled = ui_cfg.get("connection_enabled", True)
                if connection_enabled:
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    target_country = ui_cfg.get("force_country", "")
                    
                    if routing_mode != "fixed_ip":
                        available_candidates = [n for n in merged if n.get("probe_status") == "available"]
                        if routing_mode == "fixed_region" and target_country:
                            available_candidates = [
                                n for n in available_candidates 
                                if n.get("country") == target_country 
                                or vpn_utils.COUNTRY_TRANSLATIONS.get(n.get("country", ""), n.get("country", "")) == target_country
                            ]
                        elif routing_mode == "favorites":
                            fav_ids = set(ui_cfg.get("favorite_node_ids", []))
                            fav_candidates = [n for n in available_candidates if n.get("id") in fav_ids]
                            if fav_candidates:
                                available_candidates = fav_candidates
                            else:
                                fav_fail_fallback = ui_cfg.get("fav_fail_fallback", True)
                                if not fav_fail_fallback:
                                    available_candidates = []
                        
                        # Apply routing_ip_type filter for auto-connect
                        routing_ip_type = ui_cfg.get("routing_ip_type", "all")
                        if routing_ip_type == "residential":
                            available_candidates = [n for n in available_candidates if n.get("ip_type") in ("residential", "mobile")]
                        elif routing_ip_type == "hosting":
                            available_candidates = [n for n in available_candidates if n.get("ip_type") == "hosting"]
                        
                        if available_candidates:
                            auto_switch_node()

        valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])
        message = f"Fetched {len(candidates)} nodes. Tested {len(to_test_ids)} non-active nodes."
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            active_openvpn_node_id=active_openvpn_node_id,
            valid_nodes=valid_nodes_count,
        )
        return message
    except Exception as e:
        raise e
    finally:
        is_connecting = False
        maintenance_lock.release()


def collector_loop() -> None:
    global last_collector_heartbeat
    while True:
        last_collector_heartbeat = time.time()
        success = False
        try:
            print("[守护线程] 开始执行节点拉取与可用性检测周期任务...", flush=True)
            log_to_json("INFO", "Main", "开始执行节点拉取与可用性检测周期任务...")
            res = maintain_valid_nodes(force=False)
            if "没有拉取到新节点" not in res:
                success = True
            log_to_json("INFO", "Main", f"周期同步与检测任务完成，结果: {res}")
        except Exception as exc:
            err_msg = f"周期节点同步任务执行异常: {exc}"
            print(f"[错误] {err_msg}", flush=True)
            log_to_json("ERROR", "Main", err_msg)
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")
            
        if not active_openvpn_running() and not success:
            sleep_time = 30
        else:
            sleep_time = CHECK_INTERVAL_SECONDS
            
        time.sleep(sleep_time)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AimiliVPN - 安全登录</title>
<meta name="theme-color" content="#05070c" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#e8ebf1" media="(prefers-color-scheme: light)">
<script>
(function () {
  try {
    var t = localStorage.getItem("theme");
    if (t !== "light" && t !== "dark") {
      t = (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) ? "light" : "dark";
    }
    if (t === "light") document.documentElement.classList.add("light");
  } catch (e) {}
})();
</script>
<style>
  :root {
    color-scheme: dark;
    --font-ui: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "Segoe UI Variable Text", "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", system-ui, sans-serif;
    --font-mono: "SF Mono", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    --ease: cubic-bezier(0.22, 1, 0.36, 1);
    --ground: #05070c;
    --ink: #f5f5f7;
    --ink-2: #a9abb3;
    --ink-3: #8b8d95;
    --accent: #0a84ff;
    --accent-2: #4da2ff;
    --accent-fill: #0071e3;
    --accent-fill-2: #0062c4;
    --bad: #ff6b62;
    --pane: rgba(16, 19, 26, 0.42);
    --pane-line: rgba(255, 255, 255, 0.13);
    --pane-sheen: rgba(255, 255, 255, 0.13);
    --pane-spec: rgba(255, 255, 255, 0.70);
    --blur: blur(28px) saturate(180%);
    --shadow-pane: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 1px 2px rgba(0, 0, 0, 0.35), 0 18px 40px -18px rgba(0, 0, 0, 0.55), 0 44px 90px -50px rgba(0, 0, 0, 0.7);
    --field: rgba(255, 255, 255, 0.04);
    --field-line: rgba(255, 255, 255, 0.10);
    --field-focus: rgba(10, 132, 255, 0.10);
    --autofill-bg: #0d1118;
    --ring: 0 0 0 4px rgba(10, 132, 255, 0.26);
    --mesh-1: rgba(10, 132, 255, 0.34);
    --mesh-2: rgba(191, 90, 242, 0.26);
    --mesh-3: rgba(48, 209, 88, 0.16);
    --aura-1: rgba(10, 132, 255, 0.42);
    --aura-2: rgba(191, 90, 242, 0.32);
    --aura-3: rgba(90, 200, 250, 0.24);
    --aura-4: rgba(52, 132, 255, 0.44);
    --tint: rgba(255, 255, 255, 0.08);
    --tint-line: rgba(255, 255, 255, 0.12);
    --scroll-thumb: rgba(255, 255, 255, 0.18);
  }

  html.light {
    color-scheme: light;
    --ground: #e8ebf1;
    --ink: #12141a;
    --ink-2: #4f545c;
    --ink-3: #6b7079;
    --accent: #0071e3;
    --accent-2: #0a76dd;
    --accent-fill: #0071e3;
    --accent-fill-2: #0062c4;
    --bad: #bd1420;
    --pane: rgba(255, 255, 255, 0.66);
    --pane-line: rgba(16, 20, 28, 0.10);
    --pane-sheen: rgba(255, 255, 255, 0.75);
    --pane-spec: rgba(255, 255, 255, 0.95);
    --shadow-pane: inset 0 1px 0 rgba(255, 255, 255, 0.9), 0 1px 2px rgba(18, 22, 30, 0.06), 0 16px 36px -18px rgba(18, 22, 30, 0.20), 0 40px 80px -50px rgba(18, 22, 30, 0.22);
    --field: rgba(255, 255, 255, 0.58);
    --field-line: rgba(16, 20, 28, 0.12);
    --field-focus: rgba(0, 113, 227, 0.06);
    --autofill-bg: #ffffff;
    --ring: 0 0 0 4px rgba(0, 113, 227, 0.20);
    --mesh-1: rgba(0, 113, 227, 0.18);
    --mesh-2: rgba(160, 80, 230, 0.16);
    --mesh-3: rgba(20, 160, 110, 0.14);
    --aura-1: rgba(90, 175, 255, 0.45);
    --aura-2: rgba(190, 125, 245, 0.34);
    --aura-3: rgba(130, 220, 255, 0.34);
    --aura-4: rgba(150, 200, 255, 0.30);
    --tint: rgba(255, 255, 255, 0.62);
    --tint-line: rgba(16, 20, 28, 0.10);
    --scroll-thumb: rgba(16, 20, 28, 0.22);
  }

  * { box-sizing: border-box; }

  html, body { height: 100%; }

  body {
    margin: 0;
    font-family: var(--font-ui);
    font-size: 14px;
    line-height: 1.5;
    color: var(--ink);
    background: var(--ground);
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-rendering: optimizeLegibility;
  }

  ::selection { background: rgba(10, 132, 255, 0.30); }
  html.light ::selection { background: rgba(0, 113, 227, 0.18); }

  /* ── Ambient light field: the colour the glass refracts ───────────── */
  .ambient {
    position: fixed;
    inset: 0;
    z-index: -1;
    overflow: hidden;
    background: var(--ground);
  }
  .ambient::before {
    content: "";
    position: absolute;
    inset: -25%;
    background:
      radial-gradient(46% 40% at 14% 6%, var(--mesh-1) 0%, transparent 68%),
      radial-gradient(42% 40% at 86% 12%, var(--mesh-2) 0%, transparent 68%),
      radial-gradient(52% 44% at 50% 96%, var(--mesh-3) 0%, transparent 72%);
  }
  .aura {
    position: absolute;
    display: block;
    border-radius: 50%;
    filter: blur(90px);
  }
  .aura.a { width: 44vw; height: 44vw; left: -12vw; top: -14vw; background: var(--aura-1); }
  .aura.b { width: 38vw; height: 38vw; right: -10vw; top: 4vw; background: var(--aura-2); }
  .aura.c { width: 46vw; height: 46vw; left: 24vw; bottom: -26vw; background: var(--aura-3); }
  .aura.d {
    width: 34vmax;
    height: 34vmax;
    left: 50%;
    top: 52%;
    margin: -17vmax 0 0 -17vmax;
    background: var(--aura-4);
    filter: blur(70px);
  }

  /* ── Glass panel primitives ───────────────────────────────────────── */
  .pane {
    position: relative;
    background: var(--pane);
    border: 1px solid var(--pane-line);
    border-radius: 28px;
    backdrop-filter: var(--blur);
    -webkit-backdrop-filter: var(--blur);
    box-shadow: var(--shadow-pane);
  }
  .pane::before {
    content: "";
    position: absolute;
    top: -1px;
    left: 14%;
    right: 14%;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--pane-spec), transparent);
    pointer-events: none;
  }
  .pane::after {
    content: "";
    position: absolute;
    inset: 0;
    border-radius: inherit;
    background: linear-gradient(180deg, var(--pane-sheen) 0%, transparent 34%);
    opacity: 0.55;
    pointer-events: none;
  }
  .pane > * { position: relative; z-index: 1; }

  /* ── Theme control ────────────────────────────────────────────────── */
  .theme-toggle {
    position: fixed;
    top: 18px;
    right: 18px;
    z-index: 30;
    width: 38px;
    height: 38px;
    display: grid;
    place-items: center;
    padding: 0;
    border-radius: 50%;
    border: 1px solid var(--tint-line);
    background: var(--tint);
    color: var(--ink-2);
    cursor: pointer;
    backdrop-filter: blur(20px) saturate(170%);
    -webkit-backdrop-filter: blur(20px) saturate(170%);
    box-shadow: inset 0 1px 0 var(--pane-sheen), 0 6px 18px -10px rgba(0, 0, 0, 0.55);
    transition: color 0.18s var(--ease), background 0.18s var(--ease), transform 0.18s var(--ease), border-color 0.18s var(--ease);
  }
  .theme-toggle:hover { color: var(--ink); border-color: var(--pane-line); transform: translateY(-1px); }
  .theme-toggle:active { transform: scale(0.96); }
  .theme-toggle:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
  .theme-toggle svg { width: 17px; height: 17px; }
  html.light .icon-sun { display: none; }
  html:not(.light) .icon-moon { display: none; }

  /* ── Stage & card ─────────────────────────────────────────────────── */
  .stage {
    min-height: 100%;
    display: grid;
    place-items: center;
    padding: 32px 20px 40px;
  }

  .card {
    width: 100%;
    max-width: 392px;
    padding: 34px 30px 30px;
    border-radius: 28px;
    animation: card-in 0.62s var(--ease) both;
  }

  @keyframes card-in {
    from { opacity: 0; transform: translateY(12px) scale(0.985); }
    to { opacity: 1; transform: none; }
  }

  .mark {
    width: 54px;
    height: 54px;
    margin: 0 auto 18px;
    display: grid;
    place-items: center;
    border-radius: 17px;
    color: var(--accent);
    background:
      linear-gradient(160deg, rgba(10, 132, 255, 0.28), rgba(10, 132, 255, 0.06) 62%, rgba(255, 255, 255, 0.02));
    border: 1px solid rgba(10, 132, 255, 0.32);
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.28), 0 10px 22px -14px rgba(10, 132, 255, 0.9);
  }
  .mark svg { width: 26px; height: 26px; }
  html.light .mark {
    background: linear-gradient(160deg, rgba(0, 113, 227, 0.16), rgba(0, 113, 227, 0.04) 62%, rgba(255, 255, 255, 0.6));
    border-color: rgba(0, 113, 227, 0.24);
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.9), 0 10px 22px -16px rgba(0, 90, 190, 0.8);
  }

  .title {
    margin: 0 0 6px;
    font-size: 22px;
    font-weight: 600;
    letter-spacing: -0.024em;
    text-align: center;
    color: var(--ink);
  }

  .lead {
    margin: 0 0 26px;
    font-size: 13.5px;
    line-height: 1.55;
    text-align: center;
    color: var(--ink-2);
  }

  .field { margin-bottom: 14px; }
  .field:last-of-type { margin-bottom: 0; }

  .form-label {
    display: block;
    margin: 0 0 7px 2px;
    font-size: 12.5px;
    font-weight: 600;
    letter-spacing: 0.01em;
    color: var(--ink-2);
  }

  .input-field {
    width: 100%;
    height: 46px;
    padding: 0 14px;
    border-radius: 13px;
    border: 1px solid var(--field-line);
    background: var(--field);
    color: var(--ink);
    font-family: var(--font-ui);
    font-size: 15px;
    letter-spacing: 0;
    outline: none;
    box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.10);
    transition: border-color 0.16s var(--ease), box-shadow 0.16s var(--ease), background 0.16s var(--ease);
  }
  .input-field::placeholder { color: var(--ink-3); }
  .input-field:hover { border-color: rgba(10, 132, 255, 0.30); }
  .input-field:focus {
    border-color: var(--accent);
    background: var(--field-focus);
    box-shadow: var(--ring), inset 0 1px 2px rgba(0, 0, 0, 0.06);
  }
  .input-field:-webkit-autofill,
  .input-field:-webkit-autofill:hover,
  .input-field:-webkit-autofill:focus {
    -webkit-text-fill-color: var(--ink);
    box-shadow: inset 0 0 0 100px var(--autofill-bg);
    transition: background-color 9999s ease-out 0s;
  }

  .error-message {
    display: none;
    margin: 10px 2px 0;
    font-size: 12.5px;
    line-height: 1.45;
    color: var(--bad);
  }

  .submit {
    width: 100%;
    height: 46px;
    margin-top: 20px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    border: 0;
    border-radius: 14px;
    background: linear-gradient(180deg, var(--accent-fill), var(--accent-fill-2));
    color: #ffffff;
    font-family: var(--font-ui);
    font-size: 15px;
    font-weight: 600;
    letter-spacing: 0.01em;
    cursor: pointer;
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.26), 0 8px 18px -12px rgba(0, 45, 120, 0.75);
    transition: filter 0.18s var(--ease), transform 0.14s var(--ease), box-shadow 0.18s var(--ease);
  }
  .submit:hover { filter: brightness(1.08); }
  .submit:active { transform: scale(0.994); }
  .submit:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
  .submit:disabled { opacity: 0.55; cursor: progress; filter: none; transform: none; box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.18); }

  @media (max-width: 420px) {
    .stage { padding: 24px 14px 28px; }
    .card { padding: 28px 22px 24px; border-radius: 24px; }
    .title { font-size: 20px; }
    .theme-toggle { top: 12px; right: 12px; }
  }

  @media (prefers-reduced-motion: reduce) {
    .card { animation: none; }
    * { transition-duration: 0.01ms !important; }
  }
</style>
</head>
<body>
<div class="ambient" aria-hidden="true"><span class="aura a"></span><span class="aura b"></span><span class="aura c"></span><span class="aura d"></span></div>

<button id="theme_toggle" class="theme-toggle" type="button" onclick="toggleTheme()" title="切换深色/浅色" aria-label="切换深色/浅色">
  <svg id="theme_icon" class="icon-sun" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <circle cx="12" cy="12" r="4.2"></circle>
    <path d="M12 2.4v2.2M12 19.4v2.2M2.4 12h2.2M19.4 12h2.2M5.2 5.2l1.55 1.55M17.25 17.25l1.55 1.55M18.8 5.2l-1.55 1.55M6.75 17.25L5.2 18.8"></path>
  </svg>
  <svg class="icon-moon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M20.4 14.3A8.6 8.6 0 0 1 9.7 3.6a8.6 8.6 0 1 0 10.7 10.7z"></path>
  </svg>
</button>

<main class="stage">
  <section class="card pane" aria-labelledby="login_title">
    <div class="mark" aria-hidden="true">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 3.2 5 6v5.4c0 4.2 2.8 7.6 7 9.4 4.2-1.8 7-5.2 7-9.4V6l-7-2.8z"></path>
        <path d="M9.1 12.1l2.1 2.1 3.9-4.2"></path>
      </svg>
    </div>
    <h1 class="title" id="login_title">AimiliVPN</h1>
    <p class="lead">请输入您的管理账号和安全密码以继续</p>

    <form id="login_form" onsubmit="handleLogin(event)">
      <div class="field">
        <label class="form-label" for="username">管理账号</label>
        <input type="text" id="username" name="username" class="input-field" placeholder="请输入管理账号" required autocomplete="username" spellcheck="false" autocapitalize="off">
      </div>
      <div class="field">
        <label class="form-label" for="password">安全密码</label>
        <input type="password" id="password" name="password" class="input-field" placeholder="请输入安全密码" required autocomplete="current-password">
      </div>
      <div id="error_text" class="error-message" role="alert" aria-live="polite"></div>
      <button type="submit" id="submit_btn" class="submit">
        <span>登录</span>
      </button>
    </form>
  </section>
</main>

<script>
  function applyTheme(theme) {
    var light = theme === "light";
    document.documentElement.classList.toggle("light", light);
    if (document.body) document.body.classList.toggle("light", light);
  }

  function toggleTheme() {
    var next = document.documentElement.classList.contains("light") ? "dark" : "light";
    applyTheme(next);
    try { localStorage.setItem("theme", next); } catch (e) {}
  }

  async function handleLogin(e) {
    e.preventDefault();
    const uname = document.getElementById("username").value.trim();
    const pwd = document.getElementById("password").value.trim();
    const errorText = document.getElementById("error_text");
    const submitBtn = document.getElementById("submit_btn");

    errorText.style.display = "none";
    submitBtn.disabled = true;
    submitBtn.querySelector("span").textContent = "正在验证...";

    try {
      const response = await fetch("./api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: uname, password: pwd })
      });

      const data = await response.json();
      if (response.ok && data.ok) {
        window.location.reload();
      } else {
        errorText.textContent = data.error || "账号或密码不正确，请重新输入";
        errorText.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.querySelector("span").textContent = "登录";
      }
    } catch (err) {
      errorText.textContent = "连接服务器失败，请稍后重试";
      errorText.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.querySelector("span").textContent = "登录";
    }
  }
</script>
</body>
</html>"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AimiliVPN 节点池管理系统</title>
<meta name="theme-color" content="#05070c" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#e8ebf1" media="(prefers-color-scheme: light)">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script>
(function () {
  try {
    var t = localStorage.getItem("theme");
    if (t !== "light" && t !== "dark") {
      t = (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) ? "light" : "dark";
    }
    if (t === "light") document.documentElement.classList.add("light");
  } catch (e) {}
})();
</script>
<style>
  :root {
    color-scheme: dark;
    --font-ui: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "Segoe UI Variable Text", "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", system-ui, sans-serif;
    --font-mono: "SF Mono", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;

    --ease: cubic-bezier(0.22, 1, 0.36, 1);
    --ease-out: cubic-bezier(0.16, 1, 0.3, 1);

    --ground: #05070c;
    --ink: #f5f5f7;
    --ink-2: #a9abb3;
    --ink-3: #8b8d95;
    --accent: #0a84ff;
    --accent-2: #4da2ff;
    --accent-ink: #ffffff;
    --accent-fill: #0071e3;
    --accent-fill-2: #0062c4;

    --pane: rgba(20, 23, 31, 0.55);
    --pane-strong: rgba(17, 20, 28, 0.86);
    --pane-line: rgba(255, 255, 255, 0.10);
    --pane-line-strong: rgba(255, 255, 255, 0.18);
    --pane-sheen: rgba(255, 255, 255, 0.10);
    --pane-spec: rgba(255, 255, 255, 0.50);
    --blur: blur(28px) saturate(180%);
    --shadow-pane: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 1px 2px rgba(0, 0, 0, 0.35), 0 18px 40px -20px rgba(0, 0, 0, 0.55), 0 44px 90px -56px rgba(0, 0, 0, 0.7);
    --shadow-pop: inset 0 1px 0 rgba(255, 255, 255, 0.10), 0 2px 6px rgba(0, 0, 0, 0.4), 0 24px 48px -20px rgba(0, 0, 0, 0.7);
    --shadow-modal: inset 0 1px 0 rgba(255, 255, 255, 0.10), 0 2px 8px rgba(0, 0, 0, 0.4), 0 40px 90px -30px rgba(0, 0, 0, 0.8);

    --field: rgba(255, 255, 255, 0.045);
    --field-line: rgba(255, 255, 255, 0.10);
    --field-focus: rgba(10, 132, 255, 0.10);
    --autofill-bg: #0d1118;
    --ring: 0 0 0 4px rgba(10, 132, 255, 0.26);
    --option-bg: #12161d;

    --btn-tint: rgba(255, 255, 255, 0.06);
    --btn-tint-line: rgba(255, 255, 255, 0.12);
    --btn-tint-hover: rgba(255, 255, 255, 0.11);

    --tile: rgba(255, 255, 255, 0.035);
    --tile-hover: rgba(255, 255, 255, 0.065);
    --tile-line: rgba(255, 255, 255, 0.07);

    --line-soft: rgba(255, 255, 255, 0.055);
    --thead-bg: rgba(255, 255, 255, 0.035);
    --row-hover: rgba(255, 255, 255, 0.045);

    --ok: #30d158;
    --ok-ink: #5ee17f;
    --ok-bg: rgba(48, 209, 88, 0.13);
    --ok-line: rgba(48, 209, 88, 0.30);
    --ok-ring: rgba(48, 209, 88, 0.18);
    --warn: #ff9f0a;
    --warn-ink: #ffb340;
    --warn-bg: rgba(255, 159, 10, 0.14);
    --warn-line: rgba(255, 159, 10, 0.30);
    --bad: #ff453a;
    --bad-ink: #ff7b73;
    --bad-bg: rgba(255, 69, 58, 0.13);
    --bad-line: rgba(255, 69, 58, 0.30);
    --bad-fill: #c62d22;

    --row-active-bg: rgba(48, 209, 88, 0.075);
    --row-active-line: rgba(48, 209, 88, 0.35);

    --note-bg: rgba(255, 255, 255, 0.035);
    --note-line: rgba(255, 255, 255, 0.08);

    --scrim: rgba(4, 6, 10, 0.55);
    --menu-bg: rgba(20, 24, 32, 0.92);

    --term-bg: #04060b;
    --term-line: rgba(255, 255, 255, 0.07);
    --term-shadow: inset 0 2px 22px rgba(0, 0, 0, 0.6);
    --term-ink: #a9b6d6;
    --log-default: #a9b6d6;
    --log-proxy: #7cc7ff;
    --log-vpn: #5ee17f;
    --log-warn: #ffc45c;
    --log-error: #ff867e;

    --mesh-1: rgba(10, 132, 255, 0.32);
    --mesh-2: rgba(191, 90, 242, 0.24);
    --mesh-3: rgba(48, 209, 88, 0.14);
    --aura-1: rgba(10, 132, 255, 0.40);
    --aura-2: rgba(191, 90, 242, 0.30);
    --aura-3: rgba(90, 200, 250, 0.22);

    --scroll-thumb: rgba(255, 255, 255, 0.18);

    /* legacy aliases — inline styles emitted by the dashboard script */
    --bg-surface: var(--pane);
    --bg-surface-hover: var(--tile-hover);
    --border-color: var(--pane-line);
    --border-color-hover: var(--pane-line-strong);
    --text-primary: var(--ink);
    --text-secondary: var(--ink-2);
    --primary: var(--accent);
    --primary-gradient: linear-gradient(180deg, var(--accent-2), var(--accent));
    --success: var(--ok);
    --success-gradient: linear-gradient(180deg, #109143, #0a6b32);
    --danger: var(--bad);
    --danger-gradient: linear-gradient(180deg, #c62d22, #a11b12);
    --warning: var(--warn-ink);
    --active-row-bg: var(--row-active-bg);
    --active-row-border: var(--row-active-line);
  }

  html.light {
    color-scheme: light;
    --ground: #e8ebf1;
    --ink: #12141a;
    --ink-2: #4f545c;
    --ink-3: #6b7079;
    --accent: #0071e3;
    --accent-2: #0a76dd;
    --accent-fill: #0071e3;
    --accent-fill-2: #0062c4;

    --pane: rgba(255, 255, 255, 0.72);
    --pane-strong: rgba(255, 255, 255, 0.95);
    --pane-line: rgba(16, 20, 28, 0.10);
    --pane-line-strong: rgba(16, 20, 28, 0.18);
    --pane-sheen: rgba(255, 255, 255, 0.78);
    --pane-spec: rgba(255, 255, 255, 0.95);
    --shadow-pane: inset 0 1px 0 rgba(255, 255, 255, 0.9), 0 1px 2px rgba(18, 22, 30, 0.06), 0 16px 36px -20px rgba(18, 22, 30, 0.20), 0 40px 80px -56px rgba(18, 22, 30, 0.22);
    --shadow-pop: inset 0 1px 0 rgba(255, 255, 255, 0.95), 0 2px 6px rgba(18, 22, 30, 0.08), 0 22px 44px -20px rgba(18, 22, 30, 0.28);
    --shadow-modal: inset 0 1px 0 rgba(255, 255, 255, 0.95), 0 2px 8px rgba(18, 22, 30, 0.10), 0 40px 90px -30px rgba(18, 22, 30, 0.35);

    --field: rgba(255, 255, 255, 0.60);
    --field-line: rgba(16, 20, 28, 0.12);
    --field-focus: rgba(0, 113, 227, 0.05);
    --autofill-bg: #ffffff;
    --ring: 0 0 0 4px rgba(0, 113, 227, 0.20);
    --option-bg: #ffffff;

    --btn-tint: rgba(255, 255, 255, 0.62);
    --btn-tint-line: rgba(16, 20, 28, 0.10);
    --btn-tint-hover: rgba(255, 255, 255, 0.95);

    --tile: rgba(255, 255, 255, 0.50);
    --tile-hover: rgba(255, 255, 255, 0.85);
    --tile-line: rgba(16, 20, 28, 0.08);

    --line-soft: rgba(16, 20, 28, 0.06);
    --thead-bg: rgba(255, 255, 255, 0.45);
    --row-hover: rgba(255, 255, 255, 0.55);

    --ok: #0d7a3d;
    --ok-ink: #0b6b36;
    --ok-bg: rgba(16, 150, 80, 0.12);
    --ok-line: rgba(16, 150, 80, 0.26);
    --ok-ring: rgba(16, 150, 80, 0.14);
    --warn: #8a5100;
    --warn-ink: #8a5100;
    --warn-bg: rgba(200, 120, 0, 0.13);
    --warn-line: rgba(200, 120, 0, 0.26);
    --bad: #bd1420;
    --bad-ink: #b3141f;
    --bad-bg: rgba(190, 22, 34, 0.10);
    --bad-line: rgba(190, 22, 34, 0.24);
    --bad-fill: #b3141f;

    --row-active-bg: rgba(16, 150, 80, 0.07);
    --row-active-line: rgba(16, 150, 80, 0.32);

    --note-bg: rgba(16, 20, 28, 0.035);
    --note-line: rgba(16, 20, 28, 0.08);

    --scrim: rgba(24, 30, 40, 0.32);
    --menu-bg: rgba(255, 255, 255, 0.94);

    --term-bg: #f5f6f9;
    --term-line: rgba(16, 20, 28, 0.10);
    --term-shadow: inset 0 1px 2px rgba(16, 20, 28, 0.05);
    --term-ink: #33383f;
    --log-default: #3a4048;
    --log-proxy: #0b5fbf;
    --log-vpn: #0b6b36;
    --log-warn: #8a5100;
    --log-error: #ad111d;

    --mesh-1: rgba(0, 113, 227, 0.18);
    --mesh-2: rgba(160, 80, 230, 0.16);
    --mesh-3: rgba(20, 160, 110, 0.14);
    --aura-1: rgba(90, 175, 255, 0.45);
    --aura-2: rgba(190, 125, 245, 0.34);
    --aura-3: rgba(130, 220, 255, 0.34);

    --scroll-thumb: rgba(16, 20, 28, 0.22);
  }

  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; }

  body {
    margin: 0;
    min-height: 100vh;
    font-family: var(--font-ui);
    font-size: 14px;
    line-height: 1.5;
    letter-spacing: -0.004em;
    color: var(--ink);
    background: var(--ground);
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-rendering: optimizeLegibility;
  }

  ::selection { background: rgba(10, 132, 255, 0.30); }
  html.light ::selection { background: rgba(0, 113, 227, 0.18); }

  * {
    scrollbar-width: thin;
    scrollbar-color: var(--scroll-thumb) transparent;
  }
  ::-webkit-scrollbar { width: 10px; height: 10px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb {
    background: var(--scroll-thumb);
    border: 3px solid transparent;
    background-clip: padding-box;
    border-radius: 999px;
  }
  ::-webkit-scrollbar-thumb:hover { background: var(--ink-3); background-clip: padding-box; }

  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

  /* ── Ambient light field ──────────────────────────────────────────── */
  .ambient {
    position: fixed;
    inset: 0;
    z-index: -1;
    overflow: hidden;
    background: var(--ground);
    pointer-events: none;
  }
  .ambient::before {
    content: "";
    position: absolute;
    inset: -25%;
    background:
      radial-gradient(46% 40% at 12% 4%, var(--mesh-1) 0%, transparent 66%),
      radial-gradient(44% 40% at 88% 10%, var(--mesh-2) 0%, transparent 66%),
      radial-gradient(52% 44% at 46% 98%, var(--mesh-3) 0%, transparent 72%);
  }
  .aura {
    position: absolute;
    display: block;
    border-radius: 50%;
    filter: blur(100px);
  }
  .aura.a { width: 42vw; height: 42vw; left: -14vw; top: -18vw; background: var(--aura-1); }
  .aura.b { width: 34vw; height: 34vw; right: -8vw; top: 2vw; background: var(--aura-2); }
  .aura.c { width: 48vw; height: 48vw; left: 26vw; bottom: -30vw; background: var(--aura-3); }

  /* ── Glass primitives ─────────────────────────────────────────────── */
  .pane {
    position: relative;
    background: var(--pane);
    border: 1px solid var(--pane-line);
    border-radius: 20px;
    backdrop-filter: var(--blur);
    -webkit-backdrop-filter: var(--blur);
    box-shadow: var(--shadow-pane);
  }
  .pane::before {
    content: "";
    position: absolute;
    top: -1px;
    left: 18px;
    right: 18px;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--pane-spec), transparent);
    opacity: 0.7;
    pointer-events: none;
    z-index: 2;
  }
  .pane::after {
    content: "";
    position: absolute;
    inset: 0;
    border-radius: inherit;
    background: linear-gradient(180deg, var(--pane-sheen) 0%, transparent 30%);
    opacity: 0.5;
    pointer-events: none;
    z-index: 0;
  }
  .pane > * { position: relative; z-index: 1; }

  @keyframes rise {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: none; }
  }
  @keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }
  @keyframes pulse {
    0% { transform: scale(0.85); opacity: 1; }
    55% { transform: scale(1.55); opacity: 0.35; }
    100% { transform: scale(0.85); opacity: 1; }
  }
  @keyframes modalFadeIn {
    from { transform: translateY(10px) scale(0.985); opacity: 0; }
    to { transform: none; opacity: 1; }
  }

  /* ── Top bar ──────────────────────────────────────────────────────── */
  .topbar {
    position: sticky;
    top: 0;
    z-index: 60;
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto auto;
    grid-template-areas: "brand actions theme";
    align-items: center;
    gap: 14px;
    padding: 12px 26px;
    background: var(--pane);
    border-bottom: 1px solid var(--pane-line);
    backdrop-filter: var(--blur);
    -webkit-backdrop-filter: var(--blur);
    box-shadow: 0 1px 0 var(--pane-sheen) inset, 0 10px 30px -24px rgba(0, 0, 0, 0.6);
    animation: rise 0.5s var(--ease-out) both;
  }

  .brand { grid-area: brand; min-width: 0; }
  .brand-line { display: flex; align-items: center; gap: 10px; min-width: 0; }

  .mark-sm {
    flex: none;
    width: 30px;
    height: 30px;
    display: grid;
    place-items: center;
    border-radius: 9px;
    color: var(--accent);
    background: linear-gradient(160deg, rgba(10, 132, 255, 0.26), rgba(10, 132, 255, 0.05) 70%);
    border: 1px solid rgba(10, 132, 255, 0.30);
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.24);
  }
  html.light .mark-sm {
    background: linear-gradient(160deg, rgba(0, 113, 227, 0.15), rgba(0, 113, 227, 0.03) 70%);
    border-color: rgba(0, 113, 227, 0.22);
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.9);
  }
  .mark-sm svg { width: 17px; height: 17px; }

  h1 {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
    letter-spacing: -0.022em;
    color: var(--ink);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .status {
    display: none;
    margin-top: 5px;
    font-size: 12px;
    line-height: 1.5;
    color: var(--ink-2);
  }
  .status .badge { vertical-align: middle; margin: 0 3px; }

  .status-dot {
    display: inline-block;
    width: 7px;
    height: 7px;
    margin-right: 7px;
    border-radius: 50%;
    background: var(--ok);
    box-shadow: 0 0 0 3px var(--ok-ring);
    vertical-align: middle;
  }

  .actions {
    grid-area: actions;
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 8px;
    flex-wrap: wrap;
  }

  .topbar > #theme_toggle { grid-area: theme; }

  /* ── Buttons ──────────────────────────────────────────────────────── */
  .btn {
    height: 34px;
    padding: 0 13px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 7px;
    border: 1px solid var(--btn-tint-line);
    border-radius: 11px;
    background: var(--btn-tint);
    color: var(--ink);
    font-family: var(--font-ui);
    font-size: 12.5px;
    font-weight: 600;
    letter-spacing: 0.005em;
    text-decoration: none;
    white-space: nowrap;
    cursor: pointer;
    backdrop-filter: blur(18px) saturate(170%);
    -webkit-backdrop-filter: blur(18px) saturate(170%);
    box-shadow: inset 0 1px 0 var(--pane-sheen);
    transition: background 0.16s var(--ease), border-color 0.16s var(--ease), color 0.16s var(--ease), transform 0.14s var(--ease);
  }
  .btn:hover { background: var(--btn-tint-hover); border-color: var(--pane-line-strong); }
  .btn:active { transform: scale(0.98); }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
  .btn-accent:disabled { opacity: 0.8; filter: saturate(0.85); }

  .btn svg { width: 14px; height: 14px; flex: none; }

  .btn-accent {
    border-color: transparent;
    background: linear-gradient(180deg, var(--accent-fill), var(--accent-fill-2));
    color: var(--accent-ink);
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.26), 0 6px 16px -12px rgba(0, 45, 120, 0.8);
  }
  .btn-accent:hover {
    background: linear-gradient(180deg, var(--accent-fill), var(--accent-fill-2));
    filter: brightness(1.08);
    border-color: transparent;
  }

  #refresh::before {
    content: "";
    flex: none;
    width: 14px;
    height: 14px;
    background: currentColor;
    -webkit-mask: url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%23000%27%20stroke-width%3D%272.4%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3E%3Cpath%20d%3D%27M20%2011.5A8%208%200%201%201%2012%204%27%2F%3E%3Cpath%20d%3D%27M20%204.5v6h-6%27%2F%3E%3C%2Fsvg%3E") center / contain no-repeat;
    mask: url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%23000%27%20stroke-width%3D%272.4%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3E%3Cpath%20d%3D%27M20%2011.5A8%208%200%201%201%2012%204%27%2F%3E%3Cpath%20d%3D%27M20%204.5v6h-6%27%2F%3E%3C%2Fsvg%3E") center / contain no-repeat;
  }

  .btn-danger {
    height: 34px;
    padding: 0 14px;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    border-radius: 11px;
    border: 1px solid var(--bad-line);
    background: var(--bad-bg);
    color: var(--bad-ink);
    font-family: var(--font-ui);
    font-size: 12.5px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.16s var(--ease), transform 0.14s var(--ease);
  }
  .btn-danger:hover { background: var(--bad-fill); color: #fff; border-color: transparent; }
  .btn-danger:active { transform: scale(0.98); }
  .btn-danger svg { width: 15px; height: 15px; }

  .icon-btn { width: 34px; padding: 0; border-radius: 11px; }
  .icon-btn svg { width: 16px; height: 16px; }
  html.light .icon-sun { display: none; }
  html:not(.light) .icon-moon { display: none; }

  .push-end { margin-left: auto; }

  /* ── Dropdowns ────────────────────────────────────────────────────── */
  .dropdown { position: relative; }
  .dropdown-content {
    display: none;
    position: absolute;
    right: 0;
    top: calc(100% + 8px);
    min-width: 176px;
    padding: 6px;
    border-radius: 15px;
    border: 1px solid var(--pane-line);
    background: var(--menu-bg);
    backdrop-filter: var(--blur);
    -webkit-backdrop-filter: var(--blur);
    box-shadow: var(--shadow-pop);
    z-index: 500;
    animation: modalFadeIn 0.18s var(--ease-out);
  }
  .dropdown-content a {
    display: flex;
    align-items: center;
    gap: 9px;
    padding: 8px 10px;
    border-radius: 10px;
    color: var(--ink);
    font-size: 12.5px;
    font-weight: 500;
    text-decoration: none;
    transition: background 0.14s var(--ease), color 0.14s var(--ease);
  }
  .dropdown-content a:hover { background: var(--row-hover); }
  .dropdown-content a svg { width: 14px; height: 14px; flex: none; color: var(--ink-2); }
  .dropdown-content a.danger-item { color: var(--bad-ink); margin-top: 4px; border-top: 1px solid var(--line-soft); border-radius: 0 0 10px 10px; }
  .dropdown-content a.danger-item svg { color: var(--bad-ink); }
  .dropdown-content a.danger-item:hover { background: var(--bad-bg); }

  /* ── Layout ───────────────────────────────────────────────────────── */
  main {
    max-width: 1440px;
    margin: 0 auto;
    padding: 20px 26px 64px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  main > * { animation: rise 0.55s var(--ease-out) both; }
  main > *:nth-child(2) { animation-delay: 0.04s; }
  main > *:nth-child(3) { animation-delay: 0.08s; }
  main > *:nth-child(4) { animation-delay: 0.12s; }

  /* ── Active node card ─────────────────────────────────────────────── */
  .active-card {
    position: relative;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 20px;
    width: 100%;
    padding: 16px 18px;
    border-radius: 20px;
    border: 1px solid var(--pane-line);
    background: var(--pane);
    backdrop-filter: var(--blur);
    -webkit-backdrop-filter: var(--blur);
    box-shadow: var(--shadow-pane) !important;
    transition: border-color 0.25s var(--ease), background 0.25s var(--ease);
  }

  .active-card::before {
    content: "";
    position: absolute;
    top: -1px;
    left: 16px;
    right: 16px;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--pane-spec), transparent);
    opacity: 0.6;
    pointer-events: none;
  }

  .active-card-info {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    flex-wrap: wrap;
    min-width: 0;
  }
  .active-card-details { display: flex; flex-direction: column; gap: 3px; min-width: 0; flex: 1 1 200px; }

  .active-card-title {
    display: flex;
    align-items: center;
    gap: 9px;
    font-size: 13px;
    font-weight: 600;
    color: var(--ink);
    letter-spacing: 0;
  }
  .active-card-title strong { font-weight: 600; color: var(--ink); }

  .active-card-value {
    font-size: 20px;
    font-weight: 600;
    letter-spacing: -0.015em;
    color: var(--ink);
    overflow-wrap: anywhere;
  }

  .active-card-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 14px;
    margin-top: 2px;
    font-size: 12px;
    color: var(--ink-2);
  }
  .active-card-meta span strong { font-weight: 600; color: var(--ink); }

  .stat-icon-wrapper {
    flex: none;
    width: 42px;
    height: 42px;
    display: grid;
    place-items: center;
    border-radius: 13px;
    border: 1px solid var(--pane-line);
    background: var(--tile);
  }
  .stat-icon { width: 20px; height: 20px; }

  /* ── Toolbar ──────────────────────────────────────────────────────── */
  .toolbar {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    padding: 10px;
  }

  .select-wrap { position: relative; display: inline-flex; }

  select {
    appearance: none;
    -webkit-appearance: none;
    height: 34px;
    padding: 0 30px 0 12px;
    border-radius: 11px;
    border: 1px solid var(--field-line);
    background-color: var(--field);
    color: var(--ink);
    font-family: var(--font-ui);
    font-size: 12.5px;
    font-weight: 500;
    cursor: pointer;
    outline: none;
    transition: border-color 0.16s var(--ease), box-shadow 0.16s var(--ease), background-color 0.16s var(--ease);
  }
  select:hover { border-color: var(--pane-line-strong); }
  select:focus { border-color: var(--accent); box-shadow: var(--ring); }
  select option { background-color: var(--option-bg); color: var(--ink); }

  .toolbar .select-wrap select { width: auto; min-width: 132px; }
  .select-caret {
    position: absolute;
    right: 10px;
    top: 50%;
    width: 12px;
    height: 12px;
    margin-top: -6px;
    color: var(--ink-3);
    pointer-events: none;
  }

  .toolbar-btn.active {
    border-color: transparent;
    background: linear-gradient(180deg, var(--accent-fill), var(--accent-fill-2));
    color: var(--accent-ink);
  }

  /* ── Favorites panel ──────────────────────────────────────────────── */
  #favorites_panel { padding: 16px 18px; }

  .fav-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 14px;
    flex-wrap: wrap;
  }
  .fav-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13.5px;
    font-weight: 600;
    color: var(--ink);
  }
  .fav-title svg { width: 15px; height: 15px; color: var(--warn-ink); }
  .fav-desc {
    margin-top: 3px;
    font-size: 12px;
    color: var(--ink-2);
  }
  .fav-body {
    margin-top: 14px;
    padding-top: 14px;
    border-top: 1px solid var(--line-soft);
  }

  .check-row { display: flex; align-items: flex-start; gap: 10px; cursor: pointer; }
  .check-row input[type="checkbox"] {
    flex: none;
    width: 16px;
    height: 16px;
    margin: 2px 0 0;
    accent-color: var(--accent);
    cursor: pointer;
  }
  .check-row .check-text { display: flex; flex-direction: column; gap: 2px; }
  .check-title { font-size: 13px; font-weight: 500; color: var(--ink); }
  .check-hint { font-size: 12px; color: var(--ink-2); }

  #fav_fallback_warning {
    margin-top: 12px;
    padding: 10px 12px;
    border-radius: 11px;
    border: 1px solid var(--bad-line);
    background: var(--bad-bg);
    color: var(--bad-ink);
    font-size: 12px;
    line-height: 1.5;
  }

  /* ── Table ────────────────────────────────────────────────────────── */
  .table-wrapper { overflow: hidden; }

  .table-container { overflow-x: auto; }

  table {
    width: 100%;
    min-width: 840px;
    border-collapse: separate;
    border-spacing: 0;
    table-layout: fixed;
    text-align: left;
  }

  thead th {
    padding: 10px 16px;
    background: var(--thead-bg);
    border-bottom: 1px solid var(--pane-line);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--ink-3);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  thead th:first-child { border-top-left-radius: 12px; }
  thead th:last-child { border-top-right-radius: 12px; }

  tbody td {
    padding: 12px 16px;
    border-bottom: 1px solid var(--line-soft);
    font-size: 13px;
    color: var(--ink);
    vertical-align: middle;
  }
  tbody tr:last-child td { border-bottom: 0; }

  tbody tr {
    transition: background 0.14s var(--ease);
  }
  tbody tr:hover { background: var(--row-hover); }

  tbody tr.active-row {
    background: var(--row-active-bg) !important;
    outline: 1px solid var(--row-active-line);
    outline-offset: -1px;
  }
  tbody tr.active-row td { border-bottom-color: var(--row-active-line); }

  .mono {
    font-family: var(--font-mono);
    font-size: 12.5px;
    letter-spacing: -0.01em;
    font-variant-numeric: tabular-nums;
    color: var(--ink);
  }

  /* ── Badges ───────────────────────────────────────────────────────── */
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 9px;
    border: 1px solid transparent;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.005em;
    line-height: 1.45;
    white-space: nowrap;
    color: var(--ink-2);
    background: var(--tile);
    border-color: var(--tile-line);
  }

  .badge-pulse {
    display: inline-block;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
    animation: pulse 1.8s ease-in-out infinite;
  }

  .available {
    color: var(--ok-ink);
    background: var(--ok-bg);
    border-color: var(--ok-line);
  }
  .unavailable {
    color: var(--bad-ink);
    background: var(--bad-bg);
    border-color: var(--bad-line);
  }
  .not_checked {
    color: var(--warn-ink);
    background: var(--warn-bg);
    border-color: var(--warn-line);
  }
  .current-badge {
    color: var(--accent);
    background: rgba(10, 132, 255, 0.12);
    border-color: rgba(10, 132, 255, 0.28);
  }

  .latency-val {
    display: inline-block;
    padding: 1px 7px;
    border-radius: 999px;
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 500;
    font-variant-numeric: tabular-nums;
  }
  .latency-good { color: var(--ok-ink); background: var(--ok-bg); }
  .latency-medium { color: var(--warn-ink); background: var(--warn-bg); }
  .latency-poor { color: var(--bad-ink); background: var(--bad-bg); }

  /* ── Row actions ──────────────────────────────────────────────────── */
  .table-actions { display: flex; gap: 6px; flex-wrap: wrap; }

  .connect-btn,
  .test-btn {
    height: 28px;
    padding: 0 11px;
    border-radius: 9px;
    font-family: var(--font-ui);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    transition: background 0.15s var(--ease), color 0.15s var(--ease), border-color 0.15s var(--ease), transform 0.12s var(--ease);
  }
  .connect-btn {
    border: 1px solid rgba(10, 132, 255, 0.34);
    background: rgba(10, 132, 255, 0.10);
    color: var(--accent);
  }
  html.light .connect-btn {
    border-color: rgba(0, 113, 227, 0.30);
    background: rgba(0, 113, 227, 0.08);
    color: var(--accent);
  }
  .connect-btn:hover:not(:disabled) { background: var(--accent-fill); color: #fff; border-color: transparent; }
  .connect-btn:active:not(:disabled) { transform: scale(0.97); }

  .test-btn {
    border: 1px solid var(--btn-tint-line);
    background: var(--btn-tint);
    color: var(--ink-2);
  }
  .test-btn:hover:not(:disabled) { background: var(--btn-tint-hover); color: var(--ink); border-color: var(--pane-line-strong); }
  .test-btn:active:not(:disabled) { transform: scale(0.97); }

  .connect-btn:disabled,
  .test-btn:disabled { opacity: 0.35; cursor: not-allowed; }

  /* ── Pagination ───────────────────────────────────────────────────── */
  .pagination-container {
    padding: 12px 16px;
    display: none;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
    border-top: 1px solid var(--pane-line);
    font-size: 12.5px;
    color: var(--ink-2);
  }
  .pager { display: flex; align-items: center; gap: 6px; }
  .btn-sm { height: 28px; padding: 0 10px; font-size: 12px; border-radius: 9px; }

  /* ── Modals ───────────────────────────────────────────────────────── */
  .modal {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 1000;
    padding: 28px 20px;
    overflow-y: auto;
    align-items: center;
    justify-content: center;
    background: var(--scrim);
    backdrop-filter: blur(14px) saturate(120%);
    -webkit-backdrop-filter: blur(14px) saturate(120%);
  }

  .modal-content {
    position: relative;
    width: 100%;
    max-width: 460px;
    padding: 22px;
    border-radius: 24px;
    border: 1px solid var(--pane-line);
    background: var(--pane-strong);
    backdrop-filter: var(--blur);
    -webkit-backdrop-filter: var(--blur);
    box-shadow: var(--shadow-modal);
    animation: modalFadeIn 0.3s var(--ease-out) both;
    margin: auto;
  }
  .modal-content::before {
    content: "";
    position: absolute;
    top: -1px;
    left: 22%;
    right: 22%;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--pane-spec), transparent);
    opacity: 0.8;
    pointer-events: none;
  }

  .modal-wide { max-width: 560px; }
  .modal-xl { max-width: 780px; }

  .modal-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 18px;
  }
  .modal-title {
    display: flex;
    align-items: center;
    gap: 9px;
    margin: 0;
    font-size: 15.5px;
    font-weight: 600;
    letter-spacing: -0.015em;
    color: var(--ink);
  }
  .modal-title svg { width: 18px; height: 18px; color: var(--accent); }

  .modal-close {
    flex: none;
    width: 30px;
    height: 30px;
    display: grid;
    place-items: center;
    padding: 0;
    border: 1px solid transparent;
    border-radius: 50%;
    background: transparent;
    color: var(--ink-2);
    cursor: pointer;
    transition: background 0.15s var(--ease), color 0.15s var(--ease);
  }
  .modal-close:hover { background: var(--tile-hover); color: var(--ink); }
  .modal-close svg { width: 16px; height: 16px; }

  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 20px;
  }

  /* ── Forms ────────────────────────────────────────────────────────── */
  .form-group { margin-bottom: 14px; }
  .form-label {
    display: block;
    margin: 0 0 7px 2px;
    font-size: 12px;
    font-weight: 600;
    color: var(--ink-2);
    letter-spacing: 0.01em;
  }

  .input-field {
    width: 100%;
    height: 40px;
    padding: 0 12px;
    border-radius: 11px;
    border: 1px solid var(--field-line);
    background-color: var(--field);
    color: var(--ink);
    font-family: var(--font-ui);
    font-size: 13.5px;
    outline: none;
    box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.08);
    transition: border-color 0.16s var(--ease), box-shadow 0.16s var(--ease), background-color 0.16s var(--ease);
  }
  .input-field::placeholder { color: var(--ink-3); }
  .input-field:hover { border-color: var(--pane-line-strong); }
  .input-field:focus { border-color: var(--accent); background-color: var(--field-focus); box-shadow: var(--ring); }

  input[type="number"]::-webkit-outer-spin-button,
  input[type="number"]::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
  input[type="number"] { appearance: textfield; -moz-appearance: textfield; }

  select.input-field {
    appearance: none;
    -webkit-appearance: none;
    cursor: pointer;
    padding-right: 30px;
    background-image: url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%237d7f88%27%20stroke-width%3D%272.2%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3E%3Cpath%20d%3D%27M6%209l6%206%206-6%27%2F%3E%3C%2Fsvg%3E");
    background-repeat: no-repeat;
    background-position: right 10px center;
    background-size: 12px 12px;
  }

  .form-alert {
    margin-bottom: 14px;
    padding: 9px 12px;
    border-radius: 10px;
    font-size: 12.5px;
    line-height: 1.5;
  }
  .form-alert.error { color: var(--bad-ink); background: var(--bad-bg); border: 1px solid var(--bad-line); }
  .form-alert.success { color: var(--ok-ink); background: var(--ok-bg); border: 1px solid var(--ok-line); }

  .divider {
    margin: 18px 0;
    border: 0;
    border-top: 1px solid var(--line-soft);
  }

  .note {
    margin-top: 10px;
    padding: 10px 12px;
    border-radius: 11px;
    border: 1px solid var(--note-line);
    background: var(--note-bg);
    color: var(--ink-2);
    font-size: 12px;
    line-height: 1.6;
  }
  .note strong { color: var(--ink); font-weight: 600; }

  /* ── Version pill & update modal ──────────────────────────────────── */
  .version-pill {
    flex: none;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 22px;
    padding: 0 9px;
    border-radius: 999px;
    border: 1px solid var(--tile-line);
    background: var(--tile);
    color: var(--ink-3);
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.01em;
    font-variant-numeric: tabular-nums;
    cursor: pointer;
    white-space: nowrap;
    transition: background 0.16s var(--ease), border-color 0.16s var(--ease), color 0.16s var(--ease);
  }
  .version-pill:hover { color: var(--ink); background: var(--tile-hover); border-color: var(--pane-line-strong); }
  .version-pill:active { transform: scale(0.98); }
  .version-pill.has-update {
    color: var(--accent);
    background: rgba(10, 132, 255, 0.12);
    border-color: rgba(10, 132, 255, 0.30);
  }
  html.light .version-pill.has-update {
    background: rgba(0, 113, 227, 0.09);
    border-color: rgba(0, 113, 227, 0.26);
  }
  .version-pill .version-dot {
    width: 5px;
    height: 5px;
    flex: none;
    border-radius: 50%;
    background: currentColor;
    box-shadow: 0 0 0 3px rgba(10, 132, 255, 0.16);
    animation: pulse 1.8s ease-in-out infinite;
  }

  .version-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }
  .version-card {
    padding: 13px 14px;
    border-radius: 14px;
    border: 1px solid var(--tile-line);
    background: var(--tile);
    box-shadow: inset 0 1px 0 var(--pane-sheen);
    min-width: 0;
  }
  .version-card.is-current { border-color: rgba(10, 132, 255, 0.22); }
  html.light .version-card.is-current { border-color: rgba(0, 113, 227, 0.20); }
  .version-card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 9px;
  }
  .version-card-label {
    font-size: 11.5px;
    font-weight: 600;
    letter-spacing: 0.02em;
    color: var(--ink-2);
    white-space: nowrap;
  }
  .version-card .badge { font-size: 11px; padding: 1.5px 8px; }
  .version-commit {
    font-family: var(--font-mono);
    font-size: 15px;
    font-weight: 500;
    letter-spacing: -0.01em;
    color: var(--ink);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .version-subject {
    margin-top: 7px;
    font-size: 12.5px;
    line-height: 1.55;
    color: var(--ink-2);
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    min-height: 39px;
    word-break: break-word;
  }
  .version-meta {
    margin-top: 7px;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--ink-3);
    font-variant-numeric: tabular-nums;
  }
  .version-status {
    margin-top: 12px;
    padding: 10px 12px;
    border-radius: 11px;
    border: 1px solid var(--note-line);
    background: var(--note-bg);
    color: var(--ink-2);
    font-size: 12.5px;
    line-height: 1.6;
    display: flex;
    align-items: flex-start;
    gap: 8px;
  }
  .version-status svg { width: 15px; height: 15px; flex: none; margin-top: 2px; }
  .version-status strong { color: var(--ink); font-weight: 600; }
  .version-status code {
    font-family: var(--font-mono);
    font-size: 11.5px;
    padding: 1px 5px;
    border-radius: 5px;
    background: rgba(255, 255, 255, 0.06);
    color: var(--ink);
  }
  html.light .version-status code { background: rgba(16, 20, 28, 0.06); }
  .version-status.is-update { border-color: rgba(10, 132, 255, 0.28); background: rgba(10, 132, 255, 0.08); color: var(--ink); }
  html.light .version-status.is-update { border-color: rgba(0, 113, 227, 0.24); background: rgba(0, 113, 227, 0.06); }
  .version-status.is-ok { border-color: var(--ok-line); background: var(--ok-bg); color: var(--ok-ink); }
  .version-status.is-bad { border-color: var(--bad-line); background: var(--bad-bg); color: var(--bad-ink); }
  .version-status.is-warn { border-color: var(--warn-line); background: var(--warn-bg); color: var(--warn-ink); }
  .version-status.is-update strong,
  .version-status.is-ok strong,
  .version-status.is-bad strong,
  .version-status.is-warn strong { color: inherit; }

  .spinner-mini {
    width: 13px;
    height: 13px;
    flex: none;
    border-radius: 50%;
    border: 1.6px solid currentColor;
    border-right-color: transparent;
    animation: spin 0.7s linear infinite;
    opacity: 0.85;
  }

  /* ── Option cards ─────────────────────────────────────────────────── */
  .option-group {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 8px;
  }

  .option-card {
    padding: 10px 11px;
    border-radius: 11px;
    border: 1px solid var(--tile-line);
    background: var(--tile);
    cursor: pointer;
    user-select: none;
    text-align: left;
    transition: background 0.16s var(--ease), border-color 0.16s var(--ease);
  }
  .option-card:hover { background: var(--tile-hover); border-color: var(--pane-line-strong); }
  .option-card.active {
    border-color: var(--accent);
    background: rgba(10, 132, 255, 0.10);
    box-shadow: inset 0 1px 0 var(--pane-sheen);
  }
  html.light .option-card.active { background: rgba(0, 113, 227, 0.07); }

  .option-card-title { font-size: 12.5px; font-weight: 600; color: var(--ink); }
  .option-card-desc { margin-top: 2px; font-size: 11px; line-height: 1.4; color: var(--ink-2); }

  /* ── VPS recommendation ───────────────────────────────────────────── */
  .vps-links {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }
  .vps-item {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 14px;
    border-radius: 14px;
    border: 1px solid var(--tile-line);
    background: var(--tile);
    transition: background 0.16s var(--ease), border-color 0.16s var(--ease);
  }
  .vps-item:hover { background: var(--tile-hover); border-color: var(--pane-line-strong); }
  .vps-tag {
    width: fit-content;
    padding: 3px 9px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.02em;
    border: 1px solid transparent;
  }
  .tag-normal { color: var(--accent); background: rgba(10, 132, 255, 0.10); border-color: rgba(10, 132, 255, 0.24); }
  html.light .tag-normal { color: var(--accent); background: rgba(0, 113, 227, 0.08); border-color: rgba(0, 113, 227, 0.20); }
  .tag-premium { color: var(--ok-ink); background: var(--ok-bg); border-color: var(--ok-line); }
  .vps-desc { flex: 1; font-size: 12px; line-height: 1.6; color: var(--ink-2); }
  .vps-btn {
    padding: 8px 12px;
    border-radius: 10px;
    border: 1px solid var(--btn-tint-line);
    background: var(--btn-tint);
    color: var(--ink);
    font-size: 12px;
    font-weight: 600;
    text-align: center;
    text-decoration: none;
    transition: background 0.16s var(--ease), color 0.16s var(--ease), border-color 0.16s var(--ease);
  }
  .vps-btn:hover { background: var(--accent-fill); color: #fff; border-color: transparent; }
  .vps-footer {
    margin-top: 14px;
    padding-top: 12px;
    border-top: 1px solid var(--line-soft);
    font-size: 12px;
    color: var(--ink-2);
  }
  .vps-footer.left { text-align: left; line-height: 1.65; }
  .forum-link { color: var(--accent); font-weight: 600; text-decoration: none; }
  .forum-link:hover { text-decoration: underline; text-underline-offset: 3px; }

  .donate-label { display: flex; align-items: center; gap: 6px; font-weight: 600; color: var(--ink); margin-bottom: 6px; }
  .donate-label svg { width: 15px; height: 15px; color: var(--accent); }
  .donate-box {
    padding: 9px 11px;
    border-radius: 10px;
    border: 1px solid var(--note-line);
    background: var(--note-bg);
    font-family: var(--font-mono);
    font-size: 12px;
    line-height: 1.7;
    color: var(--ink-2);
    word-break: break-all;
    user-select: all;
  }
  .donate-box b { color: var(--ink); font-weight: 600; }

  /* ── Gateway ──────────────────────────────────────────────────────── */
  #gateway_services_list { display: flex; flex-direction: column; gap: 9px; margin-bottom: 18px; }
  #gateway_services_list > div {
    padding: 12px 16px;
    background: var(--tile) !important;
    border: 1px solid var(--tile-line) !important;
    border-radius: 12px !important;
  }

  .proxy-box {
    padding: 13px;
    border-radius: 14px;
    border: 1px solid var(--tile-line);
    background: var(--tile);
  }
  .proxy-box-head { display: flex; align-items: center; gap: 11px; margin-bottom: 12px; }
  .proxy-box-head h3 { margin: 0; font-size: 13px; font-weight: 600; color: var(--ink); }
  .proxy-box-head p { margin: 2px 0 0; font-size: 12px; color: var(--ink-2); }
  .proxy-readout {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    padding: 10px 12px;
    margin-bottom: 12px;
    border-radius: 11px;
    border: 1px solid var(--note-line);
    background: var(--note-bg);
    font-size: 12px;
    color: var(--ink-2);
  }
  .proxy-readout .mono { font-size: 12px; }

  /* ── Logs ─────────────────────────────────────────────────────────── */
  .logs-head {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 16px;
  }
  .logs-head .modal-title { margin-right: auto; }

  #log_filter_select {
    width: 150px;
    height: 32px;
    font-size: 12px;
  }
  .logs-head .form-label { margin: 0 2px 0 4px; white-space: nowrap; }

  .log-terminal {
    height: 400px;
    padding: 14px 16px;
    margin-bottom: 18px;
    overflow-y: auto;
    border-radius: 14px;
    border: 1px solid var(--term-line);
    background: var(--term-bg);
    box-shadow: var(--term-shadow);
    font-family: var(--font-mono);
    font-size: 11.5px;
    line-height: 1.65;
    color: var(--term-ink);
    white-space: pre-wrap;
    word-break: break-all;
    text-align: left;
  }
  .log-empty { color: var(--ink-3); text-align: center; padding-top: 150px; }

  .logs-foot { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
  .logs-foot .group { display: flex; gap: 8px; }

  /* ── Responsive ───────────────────────────────────────────────────── */
  @media (max-width: 900px) {
    .topbar {
      grid-template-columns: minmax(0, 1fr) auto;
      grid-template-areas:
        "brand theme"
        "actions actions";
      gap: 10px 12px;
      padding: 12px 16px;
    }
    .actions {
      width: 100%;
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
    }
    .actions .btn { width: 100%; }
    main { padding: 16px 16px 48px; }
    .active-card { flex-direction: column; align-items: flex-start; gap: 12px; }
    .active-card > .btn-danger { width: 100%; }
    .active-card-meta { font-size: 12px; }
  }

  @media (max-width: 620px) {
    .brand-line h1 { font-size: 14.5px; }
    .version-pill { height: 20px; padding: 0 8px; font-size: 10px; }
    .version-grid { grid-template-columns: 1fr; }
    .version-subject { min-height: 0; -webkit-line-clamp: 3; }
    .btn { height: 32px; padding: 0 11px; font-size: 12px; }
    .icon-btn { width: 32px; padding: 0; }
    .toolbar { padding: 9px; }
    .toolbar .select-wrap { flex: 1 1 46%; }
    .toolbar .select-wrap select { width: 100%; }
    .toolbar-btn.push-end { margin-left: 0; width: 100%; }
    .option-group { grid-template-columns: 1fr; }
    .vps-links { grid-template-columns: 1fr; }
    .modal { padding: 14px 12px; align-items: flex-start; }
    .modal-content { padding: 18px; border-radius: 20px; }
    .logs-foot .group { width: 100%; }
    .logs-foot .group .btn { flex: 1; }
    #logs_modal .log-terminal { height: 320px; }
    .pager { width: 100%; justify-content: space-between; }
    .table-container table { min-width: 720px; }
    thead th { padding: 9px 12px; }
    tbody td { padding: 10px 12px; }
  }

  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
      animation-duration: 0.01ms !important;
      transition-duration: 0.01ms !important;
    }
  }
</style>
</head>
<body>
<div class="ambient" aria-hidden="true"><span class="aura a"></span><span class="aura b"></span><span class="aura c"></span></div>

<header class="topbar">
  <div class="brand">
    <div class="brand-line">
      <span class="mark-sm" aria-hidden="true">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3.2 5 6v5.4c0 4.2 2.8 7.6 7 9.4 4.2-1.8 7-5.2 7-9.4V6l-7-2.8z"></path><path d="M9.1 12.1l2.1 2.1 3.9-4.2"></path></svg>
      </span>
      <h1>AimiliVPN 节点管理系统</h1>
      <button id="version_pill" class="version-pill" type="button" onclick="openVersionModal()" title="查看版本 / 检查更新" aria-label="查看版本并检查更新"><span class="version-dot" id="version_pill_dot" style="display: none;"></span><span id="version_pill_text">v—</span></button>
    </div>
    <div id="status" class="status" style="display: none;"><span class="status-dot"></span>服务加载中...</div>
  </div>

  <div class="actions">
    <button id="refresh" class="btn btn-accent" type="button">更新节点</button>

    <div class="dropdown">
      <button id="admin_btn" class="btn" type="button" aria-haspopup="true">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M16.5 7.2a4.2 4.2 0 1 1-8.4 0 4.2 4.2 0 0 1 8.4 0z"></path><path d="M12 14.2c-3.6 0-6.4 2.4-6.4 5.3h12.8c0-2.9-2.8-5.3-6.4-5.3z"></path></svg>
        管理员
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"></path></svg>
      </button>
      <div id="admin_dropdown" class="dropdown-content">
        <a href="javascript:void(0)" onclick="openCredentialsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="4.5" y="10.5" width="15" height="9.5" rx="2.6"></rect><path d="M8.2 10.5V7.6a3.8 3.8 0 0 1 7.6 0v2.9"></path></svg>
          网页安全
        </a>
        <a href="javascript:void(0)" onclick="openNetworkModal()">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3.1"></circle><path d="M12 3.6v2.4M12 18v2.4M3.6 12h2.4M18 12h2.4M6.1 6.1l1.7 1.7M16.2 16.2l1.7 1.7M17.9 6.1l-1.7 1.7M7.8 16.2l-1.7 1.7"></path></svg>
          代理设置
        </a>
        <a href="javascript:void(0)" onclick="openGatewayModal()">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="3.5" y="4.5" width="17" height="6" rx="2"></rect><rect x="3.5" y="13.5" width="17" height="6" rx="2"></rect><path d="M7.6 7.5h.01M7.6 16.5h.01"></path></svg>
          网关设置
        </a>
        <a href="javascript:void(0)" onclick="openVersionModal()">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3.6v8.6"></path><path d="M8.2 8.4l3.8 3.8 3.8-3.8"></path><path d="M4.6 15.2v2.6a2 2 0 0 0 2 2h10.8a2 2 0 0 0 2-2v-2.6"></path></svg>
          版本更新
        </a>
        <a href="javascript:void(0)" onclick="openLogsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M6.5 3.8h7l4.5 4.4v11.2a1.8 1.8 0 0 1-1.8 1.8H6.5a1.8 1.8 0 0 1-1.8-1.8V5.6a1.8 1.8 0 0 1 1.8-1.8z"></path><path d="M13.2 3.9v4.4h4.5M8.4 12.6h7M8.4 16h4.6"></path></svg>
          日志
        </a>
        <a href="javascript:void(0)" onclick="logoutAdmin()" class="danger-item">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M15.4 16.4l4.1-4.4-4.1-4.4"></path><path d="M19.2 12H9.4"></path><path d="M12.2 4.6H6.9a2 2 0 0 0-2 2v10.8a2 2 0 0 0 2 2h5.3"></path></svg>
          退出
        </a>
      </div>
    </div>

    <div class="dropdown">
      <button id="github_btn" class="btn" type="button" aria-haspopup="true">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
        GITHUB
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"></path></svg>
      </button>
      <div id="github_dropdown" class="dropdown-content">
        <a href="https://github.com/junchengluo9-del/aimilivpn" target="_blank" rel="noopener">正式版</a>
        <a href="https://github.com/junchengluo9-del/aimilivpn" target="_blank" rel="noopener">测试版</a>
      </div>
    </div>
  </div>

  <button id="theme_toggle" class="btn icon-btn" type="button" onclick="toggleTheme()" title="切换深色/浅色" aria-label="切换深色/浅色">
    <svg id="theme_icon" class="icon-sun" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="4.2"></circle>
      <path d="M12 2.4v2.2M12 19.4v2.2M2.4 12h2.2M19.4 12h2.2M5.2 5.2l1.55 1.55M17.25 17.25l1.55 1.55M18.8 5.2l-1.55 1.55M6.75 17.25L5.2 18.8"></path>
    </svg>
    <svg class="icon-moon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path d="M20.4 14.3A8.6 8.6 0 0 1 9.7 3.6a8.6 8.6 0 1 0 10.7 10.7z"></path>
    </svg>
  </button>
</header>

<main>
  <!-- 当前连接活动节点卡片 -->
  <section class="active-node-section" id="active_node_card" aria-live="polite">
    <!-- Rendered dynamically by render() -->
  </section>

  <section class="toolbar pane" aria-label="节点筛选与收藏">
    <div class="select-wrap">
      <select id="status_filter" aria-label="按状态筛选">
        <option value="all">全部节点</option>
        <option value="available">可用节点</option>
        <option value="unavailable">失效节点</option>
      </select>
      <svg class="select-caret" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 9l6 6 6-6"></path></svg>
    </div>
    <div class="select-wrap">
      <select id="country_filter" aria-label="按国家筛选">
        <option value="">所有国家</option>
      </select>
      <svg class="select-caret" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 9l6 6 6-6"></path></svg>
    </div>
    <div class="select-wrap">
      <select id="ip_type_filter" aria-label="按 IP 类型筛选">
        <option value="">所有IP类型</option>
        <option value="residential">住宅IP</option>
        <option value="hosting">机房IP</option>
      </select>
      <svg class="select-caret" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 9l6 6 6-6"></path></svg>
    </div>
    <button id="btn_favorites" class="btn toolbar-btn push-end" type="button" onclick="toggleFavoritesView()">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3.9l2.6 5.2 5.8.85-4.2 4.1 1 5.75L12 17l-5.2 2.8 1-5.75-4.2-4.1 5.8-.85L12 3.9z"></path></svg>
      收藏菜单
    </button>
  </section>

  <div id="favorites_panel" class="pane" style="display: none;">
    <div class="fav-head">
      <div>
        <div class="fav-title">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3.9l2.6 5.2 5.8.85-4.2 4.1 1 5.75L12 17l-5.2 2.8 1-5.75-4.2-4.1 5.8-.85L12 3.9z"></path></svg>
          收藏专属管理面板
        </div>
        <div class="fav-desc">在这里管理您的收藏节点过滤，以及设置出站连接漂移策略。</div>
      </div>
      <button id="btn_toggle_fav_routing" type="button" class="btn" onclick="toggleFavRouting()">启用仅用收藏出站</button>
    </div>

    <div class="fav-body">
      <label class="check-row">
        <input type="checkbox" id="fav_fail_fallback_checkbox" onchange="handleFavFallbackChange(this.checked)" checked />
        <span class="check-text">
          <span class="check-title">收藏节点失效后自动切换其他（非收藏）可用节点</span>
          <span class="check-hint">勾选此项，当所有收藏节点不可用时，系统将自动使用其他最快的非收藏可用节点，保障网络连接不中断。</span>
        </span>
      </label>
      <div id="fav_fallback_warning" style="display: none;">
        <strong>警告</strong>：您已取消勾选此项。如果当前收藏的节点均不可用，系统将<strong>无法切换</strong>到其他可用节点，可能导致网络<strong>彻底断开连接</strong>！
      </div>
    </div>
  </div>

  <div class="table-wrapper pane">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 96px;">状态</th>
            <th style="width: 210px;">IP 地址 : 端口</th>
            <th>物理位置</th>
            <th>运营主体 / ISP</th>
            <th style="width: 108px;">IP 类型</th>
            <th style="width: 178px;">操作</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>

    <!-- 分页控制栏 -->
    <div class="pagination-container">
      <div>
        显示第 <span id="page_start" style="color: var(--ink); font-weight: 600;">0</span> - <span id="page_end" style="color: var(--ink); font-weight: 600;">0</span> 条，共 <span id="filtered_count" style="color: var(--ink); font-weight: 600;">0</span> 条备选节点
      </div>
      <div class="pager">
        <button id="btn_first_page" class="btn btn-sm">首页</button>
        <button id="btn_prev_page" class="btn btn-sm">上一页</button>
        <span>
          页码 <strong id="current_page_val" style="color: var(--accent);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="btn btn-sm">下一页</button>
        <button id="btn_last_page" class="btn btn-sm">尾页</button>
      </div>
    </div>
  </div>

  <!-- Credentials Modal (网页安全设置) -->
  <div id="credentials_modal" class="modal">
    <div class="modal-content" role="dialog" aria-modal="true" aria-labelledby="credentials_title">
      <div class="modal-head">
        <h2 class="modal-title" id="credentials_title">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4.5" y="10.5" width="15" height="9.5" rx="2.6"></rect><path d="M8.2 10.5V7.6a3.8 3.8 0 0 1 7.6 0v2.9"></path></svg>
          网页安全
        </h2>
        <button type="button" class="modal-close" onclick="closeCredentialsModal()" aria-label="关闭">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"></path></svg>
        </button>
      </div>

      <div id="credentials_error" class="form-alert error" style="display: none;"></div>
      <div id="credentials_success" class="form-alert success" style="display: none;"></div>

      <form id="credentials_form" onsubmit="saveCredentials(event)">
        <div class="form-group">
          <label class="form-label" for="cred_username">管理账号</label>
          <input type="text" id="cred_username" class="input-field" required placeholder="请输入管理账号" autocomplete="off">
        </div>

        <div class="form-group">
          <label class="form-label" for="cred_password">安全密码</label>
          <input type="password" id="cred_password" class="input-field" placeholder="留空则保留当前密码" autocomplete="new-password">
        </div>

        <div class="form-group">
          <label class="form-label" for="cred_port">网页管理端口</label>
          <input type="number" id="cred_port" class="input-field" required min="1" max="65535" placeholder="8787">
        </div>

        <div class="form-group" style="margin-bottom: 0;">
          <label class="form-label" for="cred_suffix">登录安全后缀 (仅字母和数字)</label>
          <input type="text" id="cred_suffix" class="input-field" required pattern="[A-Za-z0-9]+" placeholder="EJsW2EeBo9lY" spellcheck="false" autocapitalize="off">
        </div>

        <div class="modal-actions">
          <button type="button" class="btn" onclick="closeCredentialsModal()">取消</button>
          <button type="submit" id="credentials_submit_btn" class="btn btn-accent">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Network Modal (代理及网络设置，包括出站路由) -->
  <div id="network_modal" class="modal">
    <div class="modal-content" role="dialog" aria-modal="true" aria-labelledby="network_title">
      <div class="modal-head">
        <h2 class="modal-title" id="network_title">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3.1"></circle><path d="M12 3.6v2.4M12 18v2.4M3.6 12h2.4M18 12h2.4M6.1 6.1l1.7 1.7M16.2 16.2l1.7 1.7M17.9 6.1l-1.7 1.7M7.8 16.2l-1.7 1.7"></path></svg>
          代理设置
        </h2>
        <button type="button" class="modal-close" onclick="closeNetworkModal()" aria-label="关闭">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"></path></svg>
        </button>
      </div>

      <div id="network_error" class="form-alert error" style="display: none;"></div>
      <div id="network_success" class="form-alert success" style="display: none;"></div>

      <form id="network_form" onsubmit="saveNetwork(event)">
        <div class="form-group">
          <label class="form-label" for="net_proxy_port">HTTP/SOCKS5 代理出站端口</label>
          <input type="number" id="net_proxy_port" class="input-field" required min="1024" max="65535" placeholder="7928">
        </div>

        <hr class="divider">

        <div class="form-group">
          <label class="form-label">IP 出站路由模式</label>
          <input type="hidden" id="net_routing_mode" value="auto">
          <div class="option-group" id="routing_mode_group">
            <div class="option-card active" data-value="auto" onclick="setRoutingMode('auto')">
              <div class="option-card-title">自动配置</div>
              <div class="option-card-desc">智能切换，最稳定</div>
            </div>
            <div class="option-card" data-value="fixed_ip" onclick="setRoutingMode('fixed_ip')">
              <div class="option-card-title">固定 IP</div>
              <div class="option-card-desc">锁定IP，不自动切换</div>
            </div>
            <div class="option-card" data-value="fixed_region" onclick="setRoutingMode('fixed_region')">
              <div class="option-card-title">固定地区</div>
              <div class="option-card-desc">锁定特定国家地区</div>
            </div>
          </div>
        </div>

        <div id="net_force_country_group" class="form-group" style="display: none;">
          <label class="form-label" for="net_force_country">锁定国家地区</label>
          <select id="net_force_country" class="input-field">
            <option value="">正在加载节点国家...</option>
          </select>
        </div>

        <div class="form-group">
          <label class="form-label">IP 出站类型过滤</label>
          <input type="hidden" id="net_routing_ip_type" value="all">
          <div class="option-group" id="routing_ip_type_group">
            <div class="option-card active" data-value="all" onclick="setRoutingIpType('all')">
              <div class="option-card-title">所有IP</div>
              <div class="option-card-desc">机房 + 住宅</div>
            </div>
            <div class="option-card" data-value="residential" onclick="setRoutingIpType('residential')">
              <div class="option-card-title">住宅IP</div>
              <div class="option-card-desc">静态家宽</div>
            </div>
            <div class="option-card" data-value="hosting" onclick="setRoutingIpType('hosting')">
              <div class="option-card-title">机房IP</div>
              <div class="option-card-desc">普通机房</div>
            </div>
          </div>
        </div>

        <div id="net_routing_warning" class="note">
          <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。
        </div>

        <div class="modal-actions">
          <button type="button" class="btn" onclick="closeNetworkModal()">取消</button>
          <button type="submit" id="network_submit_btn" class="btn btn-accent">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- VPS 购买推荐 Modal -->
  <div id="vps_recommend_modal" class="modal">
    <div class="modal-content modal-wide" role="dialog" aria-modal="true" aria-labelledby="vps_title">
      <div class="modal-head">
        <h2 class="modal-title" id="vps_title">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" style="color: var(--warn-ink);" aria-hidden="true"><path d="M9.6 17.2h4.8M12 3.4v1.9M18.6 5.9l-1.3 1.3M20.9 12.6h-1.9M3.1 12.6h1.9M5.4 5.9l1.3 1.3"></path><path d="M8.4 13.4a3.8 3.8 0 1 1 7.2 0c0 1.3-.9 2.1-1.4 3h-4.4c-.5-.9-1.4-1.7-1.4-3z"></path></svg>
          VPS 购买推荐
        </h2>
        <button type="button" class="modal-close" onclick="closeVpsModal()" aria-label="关闭">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"></path></svg>
        </button>
      </div>

      <div class="vps-links">
        <div class="vps-item">
          <span class="vps-tag tag-normal">RNVPS (RackNerd) 推荐</span>
          <span class="vps-desc">超低折扣价格，性价比极高，日常使用实惠方便，海外多机房可选，非常适合普通大众用户。</span>
          <a href="https://my.racknerd.com/aff.php?aff=18708" target="_blank" rel="noopener" class="vps-btn">点击进入官网</a>
        </div>
        <div class="vps-item">
          <span class="vps-tag tag-premium">搬瓦工 (Bandwagon) 推荐</span>
          <span class="vps-desc">直连三网顶级专线，经典高带宽 CN2 GIA/9929 优化线路，极致速度且超凡稳定，高端用户首选。</span>
          <a href="https://bandwagonhost.com/aff.php?aff=81790" target="_blank" rel="noopener" class="vps-btn">点击进入官网</a>
        </div>
      </div>

      <div class="vps-footer" style="text-align: center;">
        官方技术支持及优质资源交流论坛：<a href="https://339936.xyz" target="_blank" rel="noopener" class="forum-link">339936.xyz</a>
      </div>

      <div class="vps-footer left">
        <div class="donate-label">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 5.6c2.6-3.1 8-1.4 8 4 0 4.2-5.4 6.8-8 9.4-2.6-2.6-8-5.2-8-9.4 0-5.4 5.4-7.1 8-4z"></path></svg>
          捐赠支持项目开发
        </div>
        <div class="donate-box">
          <b>BNB (BSC):</b> 0xB6d78c42CEB0687A31B8cfEBE4b51b6eB8953C17<br>
          <b>TRX (TRC20):</b> TSdzCW6JvsrqcppodYjhSrku4mYmDJ9pxf
        </div>
      </div>
    </div>
  </div>

  <!-- Gateway Modal (网关自检与代理测试) -->
  <div id="gateway_modal" class="modal">
    <div class="modal-content modal-wide" role="dialog" aria-modal="true" aria-labelledby="gateway_title">
      <div class="modal-head">
        <h2 class="modal-title" id="gateway_title">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3.5" y="4.5" width="17" height="6" rx="2"></rect><rect x="3.5" y="13.5" width="17" height="6" rx="2"></rect><path d="M7.6 7.5h.01M7.6 16.5h.01"></path></svg>
          网关设置与自检
        </h2>
        <button type="button" class="modal-close" onclick="closeGatewayModal()" aria-label="关闭">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"></path></svg>
        </button>
      </div>

      <!-- 服务列表 -->
      <div id="gateway_services_list">
        <div style="text-align: center; color: var(--ink-2); padding: 20px 0;">
          <svg style="animation: spin 1s linear infinite; width: 20px; height: 20px; display: inline-block; margin-bottom: 8px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" aria-hidden="true"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>
          <div>正在加载系统网关状态...</div>
        </div>
      </div>

      <!-- 本地代理出口检测 -->
      <div class="proxy-box">
        <div class="proxy-box-head">
          <div class="stat-icon-wrapper" style="width: 34px; height: 34px; border-radius: 10px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" style="width: 17px; height: 17px; color: var(--accent);" aria-hidden="true"><path d="M8.1 16.4a5.5 5.5 0 0 1 7.8 0"></path><path d="M12 20h.01"></path><path d="M4.9 12.9a10.5 10.5 0 0 1 14.2 0"></path><path d="M1.4 8.1a16 16 0 0 1 21.2 0"></path></svg>
          </div>
          <div>
            <h3>本地代理出口检测</h3>
            <p>检测 HTTP/SOCKS5 代理出站连通性与 IP</p>
          </div>
        </div>

        <div class="proxy-readout">
          <div>测试状态：<span id="proxy_status_badge" class="badge not_checked">未检测</span></div>
          <div>
            出口 IP：<span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--ink);">-</span>
            <span id="proxy_latency_val" style="margin-left: 6px;"></span>
          </div>
        </div>

        <div style="display: flex; gap: 8px; justify-content: flex-end;">
          <button id="btn_test_proxy" class="btn btn-accent" type="button">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20.2 12a8.2 8.2 0 1 1-2.4-5.8"></path><path d="M9.4 12.2l1.9 1.9 4-4.3"></path></svg>
            开始检测
          </button>
        </div>
      </div>

      <div class="modal-actions">
        <button type="button" class="btn" onclick="closeGatewayModal()">关闭</button>
      </div>
    </div>
  </div>

  <!-- Logs Modal (日志监控与分类筛选) -->
  <div id="logs_modal" class="modal">
    <div class="modal-content modal-xl" role="dialog" aria-modal="true" aria-labelledby="logs_title">
      <div class="logs-head">
        <h2 class="modal-title" id="logs_title">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6.5 3.8h7l4.5 4.4v11.2a1.8 1.8 0 0 1-1.8 1.8H6.5a1.8 1.8 0 0 1-1.8-1.8V5.6a1.8 1.8 0 0 1 1.8-1.8z"></path><path d="M13.2 3.9v4.4h4.5M8.4 12.6h7M8.4 16h4.6"></path></svg>
          今日运行日志
        </h2>

        <label class="form-label" for="log_filter_select">日志筛选</label>
        <select id="log_filter_select" class="input-field" onchange="filterAndRenderLogs()">
          <option value="all">全部日志</option>
          <option value="proxy">代理相关 (Proxy)</option>
          <option value="vpn">VPN 连接 (VPN)</option>
          <option value="system">系统运行 (Main/Route)</option>
        </select>

        <button type="button" class="modal-close" onclick="closeLogsModal()" aria-label="关闭">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"></path></svg>
        </button>
      </div>

      <!-- Terminal Log Container -->
      <div id="log_terminal_container" class="log-terminal">
        <div class="log-empty">暂无今日运行日志记录。</div>
      </div>

      <div class="logs-foot">
        <div class="group">
          <button type="button" onclick="copyLogContent()" class="btn">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="8.5" y="8.5" width="11" height="11" rx="2.2"></rect><path d="M15.5 8.5V5.7a1.7 1.7 0 0 0-1.7-1.7H5.7A1.7 1.7 0 0 0 4 5.7v8.1a1.7 1.7 0 0 0 1.7 1.7h2.8"></path></svg>
            一键复制
          </button>
          <button type="button" onclick="exportLogContent()" class="btn">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3.6v10.2"></path><path d="M8 10.4l4 4 4-4"></path><path d="M4.6 16.2v2.1a2 2 0 0 0 2 2h10.8a2 2 0 0 0 2-2v-2.1"></path></svg>
            导出日志
          </button>
        </div>
        <button type="button" class="btn" onclick="closeLogsModal()">关闭</button>
      </div>
    </div>
  </div>

  <!-- Version Modal (版本检查与网页端在线更新) -->
  <div id="version_modal" class="modal">
    <div class="modal-content modal-wide" role="dialog" aria-modal="true" aria-labelledby="version_title">
      <div class="modal-head">
        <h2 class="modal-title" id="version_title">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3.6v8.6"></path><path d="M8.2 8.4l3.8 3.8 3.8-3.8"></path><path d="M4.6 15.2v2.6a2 2 0 0 0 2 2h10.8a2 2 0 0 0 2-2v-2.6"></path></svg>
          版本检查与更新
        </h2>
        <button type="button" class="modal-close" onclick="closeVersionModal()" aria-label="关闭">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"></path></svg>
        </button>
      </div>

      <div class="version-grid">
        <div class="version-card is-current">
          <div class="version-card-head">
            <span class="version-card-label">当前版本</span>
            <span class="badge" id="version_current_branch">—</span>
          </div>
          <div class="version-commit" id="version_current_commit">—</div>
          <div class="version-subject" id="version_current_subject">正在读取本地版本信息...</div>
          <div class="version-meta" id="version_current_meta">—</div>
        </div>
        <div class="version-card">
          <div class="version-card-head">
            <span class="version-card-label">远端最新</span>
            <span class="badge not_checked" id="version_remote_badge">未检查</span>
          </div>
          <div class="version-commit" id="version_remote_commit">—</div>
          <div class="version-subject" id="version_remote_subject">点击「检查更新」获取远端最新版本</div>
          <div class="version-meta" id="version_remote_meta">—</div>
        </div>
      </div>

      <div class="version-status" id="version_status">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="8.6"></circle><path d="M12 8.2h.01M12 11.4v4.4"></path></svg>
        <span id="version_status_text">正在加载版本信息...</span>
      </div>

      <div class="modal-actions">
        <button type="button" class="btn" onclick="closeVersionModal()">关闭</button>
        <button type="button" id="version_check_btn" class="btn" onclick="checkAppVersion()">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 11.5A8 8 0 1 1 12 4"></path><path d="M20 4.5v6h-6"></path></svg>
          检查更新
        </button>
        <button type="button" id="version_update_btn" class="btn btn-accent" data-force="0" onclick="onVersionPrimaryAction()" disabled>立即更新</button>
      </div>
    </div>
  </div>
</main>

<script>
let nodes=[], state={}, testingNodeIds = new Set();
let currentPage = 1;
const pageSize = 99999;
let currentPageNodes = [];

const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const base=p=>(p||"").split(/[\\/]/).pop();
function time(ts){return ts?new Date(ts*1000).toLocaleString():"从未"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

const translateQuality = q => {
  const dict = {"normal": "普通", "proxy": "代理", "datacenter": "数据中心", "mobile": "移动端"};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "住宅 IP", "hosting": "机房 IP", "mobile": "移动网", "proxy": "代理 IP"};
  return dict[t] || t || "-";
};

const translateCountry = c => {
  const dict = {
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
    "United Kingdom": "英国",
    "Russian Federation": "俄罗斯",
    "Russian": "俄罗斯",
    "Viet Nam": "越南",
    "Vietnam": "越南",
    "China": "中国",
    "Taiwan": "台湾",
    "Taiwan Province of China": "台湾",
    "Hong Kong": "香港",
    "Singapore": "新加坡",
    "Malaysia": "马来西亚",
    "Indonesia": "印度尼西亚",
    "India": "印度",
    "Philippines": "菲律宾",
    "Australia": "澳大利亚",
    "New Zealand": "新西兰",
    "Canada": "加拿大",
    "Ukraine": "乌克兰",
    "France": "法国",
    "Germany": "德国",
    "Netherlands": "荷兰",
    "Sweden": "瑞典",
    "Norway": "挪威",
    "Spain": "西班牙",
    "Turkey": "土耳其",
    "South Africa": "南非",
    "Brazil": "巴西",
    "Argentina": "阿根廷",
    "Chile": "智利",
    "Mexico": "墨西哥",
    "Egypt": "埃及",
    "Romania": "罗马尼亚",
    "Poland": "波兰",
    "Kazakhstan": "哈萨克斯坦",
    "Georgia": "格鲁吉亚",
    "Mongolia": "蒙古",
    "Saudi Arabia": "沙特阿拉伯",
    "Iran": "伊朗",
    "Iraq": "伊拉克",
    "Colombia": "哥伦比亚",
    "Cambodia": "柬埔寨",
    "Ireland": "爱尔兰",
    "Italy": "意大利",
    "Switzerland": "瑞士",
    "Belgium": "比利时",
    "Austria": "奥地利",
    "Denmark": "丹麦",
    "Finland": "芬兰",
    "Portugal": "葡萄牙",
    "Greece": "希腊",
    "Czech Republic": "捷克",
    "Hungary": "匈牙利",
    "Israel": "以色列",
    "United Arab Emirates": "阿联酋",
    "UAE": "阿联酋",
    "Macao": "澳门",
    "Macau": "澳门",
    "Iceland": "冰岛",
    "Luxembourg": "卢森堡"
  };
  return dict[c] || c || "-";
};

const translateStatus = s => {
  const dict = {"available": "可用", "unavailable": "不可用", "not_checked": "待检测"};
  return dict[s] || s || "待检测";
};

function getLatencyClass(ms) {
  if (!ms) return '';
  if (ms < 50) return 'latency-good';
  if (ms < 150) return 'latency-medium';
  return 'latency-poor';
}

function updateCountryFilter() {
  const select = $("country_filter");
  const selectedValue = select.value;
  const countries = Array.from(new Set(nodes.map(n => n ? translateCountry(n.country) : "").filter(Boolean))).sort();
  
  const currentOptions = Array.from(select.options).map(o => o.value).filter(Boolean);
  if (JSON.stringify(countries) === JSON.stringify(currentOptions)) {
    return;
  }
  
  select.innerHTML = '<option value="">所有国家</option>' + 
    countries.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  
  if (countries.includes(selectedValue)) {
    select.value = selectedValue;
  } else {
    select.value = "";
  }
}

function getFilteredNodes() {
  const selectedCountry = $("country_filter").value;
  const selectedIpType = $("ip_type_filter").value;
  const selectedStatus = $("status_filter").value;
  return nodes.filter(n => {
    if (!n) return false;
    if (selectedCountry && translateCountry(n.country) !== selectedCountry) {
      return false;
    }
    if (selectedIpType) {
      if (selectedIpType === "residential" && !["residential", "mobile"].includes(n.ip_type)) {
        return false;
      }
      if (selectedIpType === "hosting" && n.ip_type !== "hosting") {
        return false;
      }
    }
    if (selectedStatus === "available" && n.probe_status !== "available" && !n.active) {
      return false;
    }
    if (selectedStatus === "unavailable" && (n.probe_status !== "unavailable" || n.active)) {
      return false;
    }
    const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
    if (showFavoritesOnly && !favoriteIds.includes(n.id)) {
      return false;
    }
    return true;
  });
}

function stableSortNodes() {
  nodes.sort((a, b) => {
    if (!a || !b) return 0;
    const aScore = a.score || 0;
    const bScore = b.score || 0;
    if (bScore !== aScore) {
      return bScore - aScore;
    }
    const aId = a.id || "";
    const bId = b.id || "";
    return aId.localeCompare(bId);
  });
}

function render(){
  const activeNodeId = state.active_openvpn_node_id;
  const activeNode = nodes.find(n => n && (n.active || n.id === activeNodeId));
  
  // Render separated Active Node Card
  const activeCardContainer = $("active_node_card");
  if (state.is_connecting && !activeNode) {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--warning); box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--warning); width: 24px; height: 24px; animation: spin 2s linear infinite;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-primary);">
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: var(--warning); border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: var(--warning);"></span>正在连接</span>
              <strong>${esc(state.active_node_latency || '正在连接...')}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(state.last_check_message || '正在与 VPN 节点建立加密隧道，请稍候...')}
            </div>
          </div>
        </div>
      </div>
    `;
  } else if (activeNode) {
    const latencyClass = getLatencyClass(activeNode.latency_ms);
    const latencyText = activeNode.latency_ms ? `<span class="latency-val ${latencyClass}">${activeNode.latency_ms} ms</span>` : "-";
    const displayLocation = activeNode.location || translateCountry(activeNode.country) || "-";
    activeCardContainer.innerHTML = `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--success); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge available"><span class="badge-pulse"></span>已连接</span>
              <strong>${esc(translateCountry(activeNode.country))} 节点</strong>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>物理位置: <strong>${esc(displayLocation)}</strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">运营主体: <strong>${esc(activeNode.owner || activeNode.as_name || "-")}</strong></span>
              <span style="margin-left: 12px;">IP 类型: <strong>${esc(translateIpType(activeNode.ip_type))}</strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="disconnectNode()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          断开连接
        </button>
      </div>
    `;
  } else {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--border-color); box-shadow: none;">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.2); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--danger); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-secondary);">
              <span class="badge unavailable" style="padding: 2px 8px;">未连接</span> 当前未连接 VPN 节点
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              在下方列表中选择一个可用备用节点并点击 “切换” 按钮开始连接。
            </div>
          </div>
        </div>
      </div>
    `;
  }

  const shown = getFilteredNodes();
  
  if ($("total")) $("total").textContent = nodes.length; 
  if ($("target")) $("target").textContent = state.target_valid_nodes || 3;
  if ($("active")) $("active").textContent = activeNode ? 1 : 0; 
  
  const statusMessage = state.last_check_message || "";
  const activeNodeInfo = activeNode ? `<span class="badge available" style="margin-left:8px; padding:2px 8px;">${esc(translateCountry(activeNode.country))} (${activeNode.id})</span>` : `<span class="badge unavailable" style="margin-left:8px; padding:2px 8px;">无</span>`;
  const localProxy = state.local_proxy || `http://127.0.0.1:${state.proxy_port || 7928}`;
  if ($("status")) { $("status").innerHTML=`<span class="status-dot"></span>HTTP 代理本地接口：${localProxy} | 活动节点：${activeNodeInfo} | 状态：${statusMessage}`; }
  
  // Update proxy test status card based on background checks
  const pBadge = $("proxy_status_badge");
  const pIpVal = $("proxy_ip_val");
  const pLatVal = $("proxy_latency_val");
  const pBtn = $("btn_test_proxy");
  
  if (state.is_connecting) {
    pBadge.className = "badge";
    pBadge.style.background = "rgba(245, 158, 11, 0.15)";
    pBadge.style.color = "var(--warning)";
    pBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    pBadge.innerHTML = `<span class="badge-pulse" style="background: var(--warning);"></span>正在连接`;
    pIpVal.textContent = state.active_node_latency || "正在连接...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...")}</span>`;
    pBtn.disabled = true;
    pBtn.style.opacity = "0.5";
    pBtn.style.cursor = "not-allowed";
  } else {
    pBtn.disabled = false;
    pBtn.style.opacity = "";
    pBtn.style.cursor = "";
    pBadge.style.background = "";
    pBadge.style.color = "";
    pBadge.style.borderColor = "";
    if (state.proxy_ok !== undefined) {
      if (state.proxy_ok) {
        pBadge.className = "badge available";
        pBadge.textContent = "可用";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "不可用";
        pIpVal.textContent = "-";
        pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px; max-width: 450px; display: inline-block; white-space: normal; line-height: 1.4; text-align: left;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "连接失败")}</span>`;
      }
    } else {
      pBadge.className = "badge not_checked";
      pBadge.textContent = "未检测";
      pIpVal.textContent = "-";
      if (state.last_check_message) {
        pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
      } else {
        pLatVal.innerHTML = "";
      }
    }
  }

  updateFavPanelUI();

  // Pagination calculation
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  // Render table rows
  if (currentPageNodes.length === 0) {
    $("rows").innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-secondary); padding: 48px 0;">未找到符合过滤条件的备选节点。</td></tr>`;
  } else {
    $("rows").innerHTML=currentPageNodes.map(n=>{
      if (!n) return '';
      const isCurrentlyActive = activeNode && n.id === activeNode.id;
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';
      
      const badgeClass = isCurrentlyActive ? 'available' : (n.probe_status || 'not_checked');
      const badgeText = isCurrentlyActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status);
      const latencyClass = getLatencyClass(n.latency_ms);
      const latencyText = n.latency_ms ? `<span class="latency-val ${latencyClass}">${n.latency_ms} ms</span>` : "-";
      const displayLocation = n.location || translateCountry(n.country) || "-";
      
      const isTesting = testingNodeIds.has(n.id);
      const testSpinner = `<svg style="animation: spin 1s linear infinite; width: 12px; height: 12px; display: inline-block; margin-right: 4px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>`;
      const testBtnText = isTesting ? `${testSpinner}检测中` : '检测';
      const testBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" ${isTesting ? 'disabled' : ''} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>`;
      
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      const isUnavailable = n.probe_status === "unavailable";
      const connectBtn = isCurrentlyActive 
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">已连接</button>`
        : `<button class="connect-btn" ${(isUnavailable || state.is_connecting) ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : ''} onclick="connectNode('${esc(n.id)}')">切换</button>`;
      
      const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
      const isFav = favoriteIds.includes(n.id);
      const favBtn = isFav 
        ? `<button class="test-btn" style="color: var(--warning); border-color: rgba(245, 158, 11, 0.4); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">★ 已收藏</button>`
        : `<button class="test-btn" style="color: var(--text-secondary); border-color: var(--border-color); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">☆ 收藏</button>`;

      return `<tr ${rowClass}>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td class="mono" style="white-space: nowrap; max-width: 220px; overflow: hidden; text-overflow: ellipsis;" title="${esc(n.ip||n.remote_host)}:${n.remote_port||""}">${esc(n.ip||n.remote_host)}:${n.remote_port||""}</td>
        <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${esc(displayLocation)}">${esc(displayLocation)}</td>
        <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${esc(n.owner||n.as_name||"-")}">${esc(n.owner||n.as_name||"-")}</td>
        <td style="white-space: nowrap; max-width: 110px; overflow: hidden; text-overflow: ellipsis;" title="${esc(translateIpType(n.ip_type))}">${esc(translateIpType(n.ip_type))}</td>
        <td>
          <div class="table-actions">
            ${favBtn}
            ${connectBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  // Render pagination controls
  $("page_start").textContent = shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = shown.length;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;
  
  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;
}

// Hook up page buttons events
$("btn_first_page").onclick = () => { currentPage = 1; render(); };
$("btn_prev_page").onclick = () => { if (currentPage > 1) { currentPage--; render(); } };
$("btn_next_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage < totalPages) { currentPage++; render(); }
};
$("btn_last_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  currentPage = totalPages;
  render();
};

async function testNode(btn, id, event){
  if (event) event.stopPropagation();
  testingNodeIds.add(id);
  render();
  
  try {
    const response = await fetch("./api/test_node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok && result.node) {
      const idx = nodes.findIndex(n => n && n.id === id);
      if (idx !== -1) {
        nodes[idx] = result.node;
      }
    }
  } catch (e) {
  } finally {
    testingNodeIds.delete(id);
    render();
  }
}

async function toggleFavorite(id, event) {
  if (event) event.stopPropagation();
  try {
    const response = await fetch("./api/toggle_favorite", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok) {
      state.favorite_node_ids = Array.isArray(result.favorite_node_ids) ? result.favorite_node_ids : [];
      render();
    }
  } catch (e) {
    console.error("切换收藏失败", e);
  }
}

let pollInterval = null;

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    try {
      const resp = await fetch("./api/nodes");
      const data = await resp.json();
      nodes = Array.isArray(data.nodes) ? data.nodes : [];
      state = data.state || {};
      stableSortNodes();
      updateCountryFilter();
      render();
      
      if (!state.is_connecting) {
        clearInterval(pollInterval);
        pollInterval = null;
        try {
          await fetch("./api/test_proxy", { method: "POST" });
        } catch(pe){}
        load();
      }
    } catch(pe) {
      clearInterval(pollInterval);
      pollInterval = null;
      load();
    }
  }, 1000);
}

async function connectNode(id){
  state.is_connecting = true;
  state.active_openvpn_node_id = id;
  state.active_node_latency = "正在连接";
  state.last_check_message = "正在发送连接请求...";
  render();
  
  startConnectionPolling();
  
  try {
    const r = await fetch("./api/connect",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({id})
    });
    const result = await r.json();
    if (!result.ok) {
      alert("连接失败: " + (result.error || "未知错误"));
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
      state.is_connecting = false;
      render();
      return;
    }
  } catch(e) {
    alert("连接请求错误");
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    state.is_connecting = false;
    render();
  }
}

async function disconnectNode(){
  if (!confirm("确定要断开当前的 VPN 连接吗？")) return;
  try {
    const response = await fetch("./api/disconnect", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      try {
        await fetch("./api/test_proxy", { method: "POST" });
      } catch(pe){}
      load();
    } else {
      alert("断开连接失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    alert("请求断开连接失败");
  }
}





async function load(){
  const r=await fetch("./api/nodes"); 
  const d=await r.json(); 
  nodes=Array.isArray(d.nodes) ? d.nodes : []; 
  state=d.state||{}; 
  
  stableSortNodes();
  updateCountryFilter();
  render();

  if (state.is_connecting) {
    startConnectionPolling();
  }
}
$("country_filter").onchange=()=>{ currentPage = 1; render(); };
$("ip_type_filter").onchange=()=>{ currentPage = 1; render(); };
$("status_filter").onchange=()=>{ currentPage = 1; render(); };

$("refresh").onclick=async()=>{ 
  $("refresh").disabled=true; 
  $("refresh").textContent="正在后台更新..."; 
  try{await fetch("./api/refresh_nodes",{method:"POST"}); await load();} 
  catch(e){}
  setTimeout(()=>{
    $("refresh").disabled=false; 
    $("refresh").textContent="更新节点";
  }, 3000);
};
$("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");
  
  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>测试中...`;
  badge.className = "badge not_checked";
  badge.textContent = "检测中...";
  ipVal.textContent = "-";
  latVal.textContent = "";
  
  try {
    const response = await fetch("./api/test_proxy", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "可用";
      ipVal.textContent = result.ip || "-";
      
      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "不可用";
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">连接失败</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "网络错误";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">请求出错</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 测试代理`;
  }
};

// Admin dropdown toggle & GitHub dropdown toggle
const adminBtn = $("admin_btn");
const adminDropdown = $("admin_dropdown");
const githubBtn = $("github_btn");
const githubDropdown = $("github_dropdown");

if (adminBtn && adminDropdown) {
  adminBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = adminDropdown.style.display === "block";
    adminDropdown.style.display = isShow ? "none" : "block";
    if (githubDropdown) githubDropdown.style.display = "none";
  };
}

if (githubBtn && githubDropdown) {
  githubBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = githubDropdown.style.display === "block";
    githubDropdown.style.display = isShow ? "none" : "block";
    if (adminDropdown) adminDropdown.style.display = "none";
  };
}

document.addEventListener("click", () => {
  if (adminDropdown) adminDropdown.style.display = "none";
  if (githubDropdown) githubDropdown.style.display = "none";
});

let showFavoritesOnly = false;

function toggleFavoritesView() {
  showFavoritesOnly = !showFavoritesOnly;
  currentPage = 1;
  render();
}

function updateFavPanelUI() {
  const panel = $("favorites_panel");
  if (!panel) return;
  panel.style.display = showFavoritesOnly ? "block" : "none";
  
  const btn = $("btn_favorites");
  if (btn) {
    if (showFavoritesOnly) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  }

  if (showFavoritesOnly && state) {
    const fallbackCheckbox = $("fav_fail_fallback_checkbox");
    if (fallbackCheckbox) {
      fallbackCheckbox.checked = !!state.fav_fail_fallback;
    }
    
    const warningDiv = $("fav_fallback_warning");
    if (warningDiv) {
      warningDiv.style.display = state.fav_fail_fallback ? "none" : "block";
    }

    const favRoutingBtn = $("btn_toggle_fav_routing");
    if (favRoutingBtn) {
      if (state.routing_mode === "favorites") {
        favRoutingBtn.textContent = "禁用仅用收藏出站";
        favRoutingBtn.style.background = "var(--danger-gradient)";
        favRoutingBtn.style.borderColor = "transparent";
        favRoutingBtn.style.color = "#ffffff";
        favRoutingBtn.style.boxShadow = "none";
      } else {
        favRoutingBtn.textContent = "启用仅用收藏出站";
        favRoutingBtn.style.background = "var(--btn-tint)";
        favRoutingBtn.style.borderColor = "var(--border-color)";
        favRoutingBtn.style.color = "var(--text-primary)";
        favRoutingBtn.style.boxShadow = "none";
      }
    }
  }
}

async function toggleFavRouting() {
  if (!state) return;
  const newMode = state.routing_mode === "favorites" ? "auto" : "favorites";
  
  state.routing_mode = newMode;
  updateFavPanelUI();
  
  try {
    const res = await fetch("./api/update_routing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_mode: newMode,
        force_country: state.force_country || "",
        routing_ip_type: state.routing_ip_type || "all",
        fav_fail_fallback: state.fav_fail_fallback !== false
      })
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      load();
    } else {
      alert("更新出站路由设置失败: " + (data.error || "未知错误"));
      load();
    }
  } catch (err) {
    alert("连接服务器失败，请稍后重试");
    load();
  }
}

async function handleFavFallbackChange(checked) {
  if (!state) return;
  
  if (!checked) {
    alert("⚠️ 警告：不勾选此项可能在所有收藏节点失效时造成网络彻底断开连接，无法自动切换到其他非收藏的可用节点！");
  }
  
  state.fav_fail_fallback = checked;
  updateFavPanelUI();
  
  try {
    const res = await fetch("./api/update_routing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_mode: state.routing_mode || "auto",
        force_country: state.force_country || "",
        routing_ip_type: state.routing_ip_type || "all",
        fav_fail_fallback: checked
      })
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      load();
    } else {
      alert("更新失败: " + (data.error || "未知错误"));
      load();
    }
  } catch (err) {
    alert("连接服务器失败，请稍后重试");
    load();
  }
}

function selectOptionCard(groupName, value) {
  if (groupName === 'routing_mode') {
    const input = $("net_routing_mode");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#routing_mode_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
    
    handleRoutingModeChange(value);
  } else if (groupName === 'routing_ip_type') {
    const input = $("net_routing_ip_type");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#routing_ip_type_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
  }
}

function setRoutingMode(value) {
  selectOptionCard('routing_mode', value);
}

function setRoutingIpType(value) {
  selectOptionCard('routing_ip_type', value);
}

function handleRoutingModeChange(mode) {
  const countryGroup = $("net_force_country_group");
  const warningDiv = $("net_routing_warning");
  
  if (mode === "fixed_region") {
    countryGroup.style.display = "block";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `<strong>固定地区</strong>：限制仅连接选定国家的节点，且后台仅并发测速该国家的节点。如果该国的所有可用节点都失效，会造成代理中断且<strong>绝不自动切换到其他国家</strong>的节点。`;
  } else if (mode === "favorites") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `<strong>仅用收藏</strong>：只连接和切换您收藏的节点。如果所有收藏的节点均失效，系统不会自动切换到未收藏的节点。请确保收藏列表中有足够多且可用的节点。`;
  } else if (mode === "fixed_ip") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `<strong>固定IP</strong>：锁定当前连接的节点。不管该节点是否失效，系统都绝不自动切换至其他IP；如果节点由于网络故障失效，会造成代理中断（但如果OpenVPN连接意外退出，脚本将尝试为您在后台重新拉起连接同一IP）。<br><strong>提示</strong>：您可以在主页 of 节点列表中直接点击“连接”按钮来选择并锁定不同的IP节点。`;
  } else {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--text-secondary)";
    warningDiv.style.background = "var(--note-bg)";
    warningDiv.style.border = "1px solid var(--note-line)";
    warningDiv.innerHTML = `<strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。`;
  }
}

function populateRoutingCountries() {
  const select = $("net_force_country");
  if (!select) return;
  const countMap = {};
  nodes.forEach(n => {
    const c = translateCountry(n.country);
    if (c) {
      countMap[c] = (countMap[c] || 0) + 1;
    }
  });
  
  const countries = Object.keys(countMap).sort();
  let html = '<option value="">请选择要锁定的国家...</option>';
  countries.forEach(c => {
    html += `<option value="${esc(c)}">${esc(c)} (${countMap[c]}个节点)</option>`;
  });
  select.innerHTML = html;
  
  if (state) {
    select.value = state.force_country ? translateCountry(state.force_country) : "";
  }
}

function openCredentialsModal() {
  $("credentials_error").style.display = "none";
  $("credentials_success").style.display = "none";
  $("credentials_form").reset();
  if (state) {
    $("cred_username").value = state.username || "";
    $("cred_password").value = "";
    $("cred_port").value = state.port || 8787;
    $("cred_suffix").value = state.secret_path || "";
  }
  $("credentials_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeCredentialsModal() {
  $("credentials_modal").style.display = "none";
}

async function saveCredentials(e) {
  e.preventDefault();
  const errorDivEl = $("credentials_error");
  const successDiv = $("credentials_success");
  const submitBtn = $("credentials_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const username = $("cred_username").value.trim();
  const password = $("cred_password").value.trim();
  const port = parseInt($("cred_port").value);
  const suffix = $("cred_suffix").value.trim();
  
  if (!username || (!password && !(state && state.password_set))) {
    errorDivEl.textContent = "用户名不能为空；首次设置时密码不能为空";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (isNaN(port) || port < 1 || port > 65535) {
    errorDivEl.textContent = "网页管理端口范围必须在 1 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (!/^[A-Za-z0-9]+$/.test(suffix)) {
    errorDivEl.textContent = "登录安全后缀仅能由英文字母和数字组成";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (state && port === state.proxy_port) {
    errorDivEl.textContent = "网页管理端口不能与代理出站端口相同";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetch("./api/update_credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: username,
        password: password,
        port: port,
        secret_path: suffix
      })
    });
    
    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.restart_needed) {
        successDiv.textContent = "保存成功！网页管理端口或路径已变更，页面将在 4 秒内自动跳转...";
        successDiv.style.display = "block";
        
        const inputs = $("credentials_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);
        
        setTimeout(() => {
          const protocol = window.location.protocol;
          const host = window.location.hostname;
          window.location.href = `${protocol}//${host}:${port}/${suffix}/`;
        }, 4000);
      } else {
        successDiv.textContent = data.reauth_required ? "账号密码保存成功，请重新登录..." : "账号密码保存成功，已即时生效！";
        successDiv.style.display = "block";
        setTimeout(() => {
          if (data.reauth_required) {
            window.location.reload();
          } else {
            closeCredentialsModal();
            load();
          }
        }, 1500);
      }
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}

function openNetworkModal() {
  $("network_error").style.display = "none";
  $("network_success").style.display = "none";
  $("network_form").reset();
  
  if (state) {
    $("net_proxy_port").value = state.proxy_port || 7928;
    const mode = state.routing_mode || "auto";
    const ipType = state.routing_ip_type || "all";
    
    selectOptionCard('routing_mode', mode);
    selectOptionCard('routing_ip_type', ipType);
  }
  
  populateRoutingCountries();
  $("network_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeNetworkModal() {
  $("network_modal").style.display = "none";
}

async function saveNetwork(e) {
  e.preventDefault();
  const errorDivEl = $("network_error");
  const successDiv = $("network_success");
  const submitBtn = $("network_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const proxyPort = parseInt($("net_proxy_port").value);
  const routingMode = $("net_routing_mode").value;
  const forceCountry = $("net_force_country").value;
  const routingIpType = $("net_routing_ip_type").value;
  
  if (isNaN(proxyPort) || proxyPort < 1024 || proxyPort > 65535) {
    errorDivEl.textContent = "代理出站端口范围必须在 1024 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }

  if (state && proxyPort === state.port) {
    errorDivEl.textContent = "代理出站端口不能与网页管理端口相同";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (routingMode === "fixed_region" && !forceCountry) {
    errorDivEl.textContent = "请选择一个要锁定的目标国家";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetch("./api/update_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        proxy_port: proxyPort,
        routing_mode: routingMode,
        force_country: forceCountry,
        routing_ip_type: routingIpType
      })
    });
    
    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.restart_needed) {
        successDiv.textContent = "保存成功！代理出站端口已变更，页面将在 4 秒内自动刷新...";
        successDiv.style.display = "block";
        
        const inputs = $("network_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);
        
        setTimeout(() => {
          window.location.reload();
        }, 4000);
      } else {
        successDiv.textContent = "配置保存成功，已即时生效！";
        successDiv.style.display = "block";
        setTimeout(() => {
          closeNetworkModal();
          load();
        }, 1500);
      }
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}



function openVpsModal() {
  $("vps_recommend_modal").style.display = "flex";
}

function closeVpsModal() {
  $("vps_recommend_modal").style.display = "none";
}

async function logoutAdmin() {
  try {
    const res = await fetch("./api/logout", { method: "POST" });
    if (res.ok) {
      window.location.reload();
    }
  } catch (err) {
    console.error("退出登录失败", err);
    window.location.reload();
  }
}

// 页面加载时自动初始化数据
load();

// ── 版本检查与网页端在线更新 ────────────────────────────────────────────
let appVersionBusy = false;
let appUpdateRunning = false;
let appReconnectTimer = null;

function fmtVersionTime(iso) {
  if (!iso) return "时间未知";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
  const p = n => (n < 10 ? "0" + n : String(n));
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function setVersionStatus(kind, html) {
  const box = $("version_status");
  if (!box) return;
  box.className = "version-status" + (kind ? " is-" + kind : "");
  $("version_status_text").innerHTML = html;
}

// 更新成功后立即把卡片/版本标记刷成新版本，避免重启前还显示“落后 N 个提交”
function applyVersionAfterUpdate(data) {
  const commit = data.new_commit || "";
  $("version_current_commit").textContent = commit ? "v" + commit : "—";
  if (data.new_message) $("version_current_subject").textContent = data.new_message;
  if (data.new_date) $("version_current_meta").textContent = "提交于 " + fmtVersionTime(data.new_date);
  $("version_remote_commit").textContent = commit ? "v" + commit : "—";
  if (data.new_message) $("version_remote_subject").textContent = data.new_message;
  if (data.new_date) $("version_remote_meta").textContent = "提交于 " + fmtVersionTime(data.new_date);
  $("version_remote_badge").className = "badge available";
  $("version_remote_badge").textContent = "已是最新";
  if (commit) $("version_pill_text").textContent = "v" + commit;
  $("version_pill").classList.remove("has-update");
  $("version_pill_dot").style.display = "none";
  $("version_update_btn").className = "btn btn-accent";
  $("version_update_btn").disabled = true;
  $("version_check_btn").disabled = true;
}

function renderAppVersion(info) {
  const pill = $("version_pill");
  const pillText = $("version_pill_text");
  const dot = $("version_pill_dot");
  const hasUpdate = !!(info && info.has_update);
  if (info && info.current_commit) pillText.textContent = "v" + info.current_commit;
  pill.classList.toggle("has-update", hasUpdate);
  dot.style.display = hasUpdate ? "inline-block" : "none";
  pill.title = hasUpdate ? `发现新版本（当前 v${info.current_commit}）` : "查看版本 / 检查更新";

  $("version_current_branch").textContent = (info && info.branch) ? info.branch : "—";
  $("version_current_commit").textContent = (info && info.current_commit) ? "v" + info.current_commit : "—";
  $("version_current_subject").textContent = (info && info.current_message) || "未读取到提交说明";
  $("version_current_meta").textContent = (info && info.current_date) ? "提交于 " + fmtVersionTime(info.current_date) : "";

  const remoteBadge = $("version_remote_badge");
  if (!info || !info.checked_remote) {
    remoteBadge.className = "badge not_checked";
    remoteBadge.textContent = "未检查";
    $("version_remote_commit").textContent = "—";
    $("version_remote_subject").textContent = "点击「检查更新」获取远端最新版本";
    $("version_remote_meta").textContent = "";
  } else {
    $("version_remote_commit").textContent = info.remote_commit ? "v" + info.remote_commit : "—";
    $("version_remote_subject").textContent = info.remote_message || "未读取到提交说明";
    $("version_remote_meta").textContent = info.remote_date ? "提交于 " + fmtVersionTime(info.remote_date) : "";
    remoteBadge.className = "badge " + (info.has_update ? "current-badge" : "available");
    remoteBadge.textContent = info.has_update ? ("落后 " + info.commits_behind + " 个提交") : "已是最新";
  }

  const updateBtn = $("version_update_btn");
  const canUpdate = !!(info && info.git_available !== false && info.is_git_repo);
  if (!appUpdateRunning) {
    // 有更新时主按钮为高亮的「立即更新」；已是最新时降级为备用的「强制重新拉取」
    updateBtn.className = hasUpdate ? "btn btn-accent" : "btn";
    updateBtn.dataset.force = hasUpdate ? "0" : "1";
    updateBtn.disabled = !canUpdate;
    updateBtn.textContent = hasUpdate ? "立即更新" : "强制重新拉取";
  }

  if (info && info.ok === false) {
    setVersionStatus("bad", esc(info.error || "无法读取版本信息"));
    return;
  }
  const dirtyNote = (info && info.local_dirty)
    ? "<br>注意：安装目录存在未提交的本地改动，更新会以远端代码强制覆盖。"
    : "";
  if (!info || !info.checked_remote) {
    setVersionStatus("", "本地版本已读取。点击「检查更新」连接 GitHub 获取远端最新版本。" + dirtyNote);
  } else if (info.has_update) {
    const extra = (info.commits_ahead > 0)
      ? `<br>本地另有 <code>${info.commits_ahead}</code> 个提交领先于远端，更新后会被远端版本覆盖。`
      : "";
    setVersionStatus("update", `<strong>发现新版本</strong>：远端比当前多 <code>${info.commits_behind}</code> 个提交，可直接在此更新，服务会自动重启。` + extra + dirtyNote);
  } else {
    const aheadNote = (info.commits_ahead > 0)
      ? `<br>本地有 <code>${info.commits_ahead}</code> 个提交未推送到远端（可能是本地修改）。`
      : "";
    setVersionStatus("ok", `<strong>已是最新版本</strong>：当前代码与远端 ${esc(info.branch || "")} 分支一致。` + aheadNote + dirtyNote);
  }
}

async function loadAppVersionQuick() {
  try {
    const res = await fetch("./api/app_version", { cache: "no-store" });
    const data = await res.json();
    renderAppVersion(data);
  } catch (e) {
    // 静默失败：顶栏保留占位
  }
}

async function checkAppVersion() {
  if (appVersionBusy) return;
  appVersionBusy = true;
  const checkBtn = $("version_check_btn");
  const prevHtml = checkBtn.innerHTML;
  checkBtn.disabled = true;
  checkBtn.innerHTML = '<span class="spinner-mini"></span>检查中';
  setVersionStatus("", "正在连接 GitHub 获取远端最新版本...");
  try {
    const res = await fetch("./api/app_version?check=1", { cache: "no-store" });
    const data = await res.json();
    renderAppVersion(data);
  } catch (err) {
    setVersionStatus("bad", "连接服务器失败，请稍后重试。");
  } finally {
    appVersionBusy = false;
    checkBtn.disabled = false;
    checkBtn.innerHTML = prevHtml;
  }
}

function openVersionModal() {
  $("admin_dropdown").style.display = "none";
  $("version_modal").style.display = "flex";
  checkAppVersion();
}

function closeVersionModal() {
  $("version_modal").style.display = "none";
}

function onVersionPrimaryAction() {
  const btn = $("version_update_btn");
  runAppUpdate(btn.dataset.force === "1");
}

async function runAppUpdate(force) {
  if (appUpdateRunning) return;
  if (force && !confirm("强制重新拉取会用远端代码覆盖安装目录中的代码（保留 vpngate_data 运行数据），确定继续？")) return;
  appUpdateRunning = true;
  const updateBtn = $("version_update_btn");
  const checkBtn = $("version_check_btn");
  const prevLabel = updateBtn.textContent;
  updateBtn.className = "btn btn-accent";
  updateBtn.disabled = true;
  updateBtn.innerHTML = '<span class="spinner-mini"></span>正在更新';
  checkBtn.disabled = true;
  setVersionStatus("", "正在从 GitHub 拉取最新代码，请稍候（通常几秒，网络较慢时可能更久）...");
  try {
    const res = await fetch("./api/update_app", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ force: !!force })
    });
    let data = {};
    try { data = await res.json(); } catch (e) { data = {}; }

    if (res.ok && data.ok && data.updated) {
      applyVersionAfterUpdate(data);
      const oldC = data.old_commit ? "v" + data.old_commit : "旧版本";
      const newC = data.new_commit ? "v" + data.new_commit : "新版本";
      startVersionReconnect(4, `更新成功（${esc(oldC)} → ${esc(newC)}）`);
      return;
    }

    if (data.needs_force) {
      setVersionStatus("warn", esc(data.message || "本地代码与远端不一致"));
      checkBtn.disabled = false;
      updateBtn.className = "btn";
      updateBtn.dataset.force = "1";
      updateBtn.disabled = false;
      updateBtn.textContent = "强制重新拉取";
      appUpdateRunning = false;
      return;
    }

    if (res.ok && data.ok) {
      setVersionStatus("ok", `<strong>${esc(data.message || "当前已是最新版本")}</strong>`);
      checkBtn.disabled = false;
      updateBtn.className = "btn";
      updateBtn.dataset.force = "1";
      updateBtn.disabled = false;
      updateBtn.textContent = "强制重新拉取";
      appUpdateRunning = false;
      return;
    }

    setVersionStatus("bad", "更新失败：" + esc(data.error || data.message || "请稍后重试"));
  } catch (err) {
    setVersionStatus("bad", "请求更新失败，服务可能正在重启；若页面无响应请手动刷新并重新登录。");
  }
  appUpdateRunning = false;
  checkBtn.disabled = false;
  if (updateBtn.innerHTML.indexOf("spinner-mini") >= 0) updateBtn.textContent = prevLabel;
}

function startVersionReconnect(waitSeconds, lead) {
  if (appReconnectTimer) clearInterval(appReconnectTimer);
  let elapsed = 0;
  const giveUpAfter = 90;
  const head = lead || "更新已应用";
  $("version_update_btn").className = "btn btn-accent";
  $("version_update_btn").disabled = true;
  $("version_update_btn").innerHTML = '<span class="spinner-mini"></span>等待服务重启';
  appReconnectTimer = setInterval(async () => {
    elapsed += 1;
    if (elapsed <= waitSeconds) {
      setVersionStatus("ok", `<strong>${head}</strong>，服务正在重启，约 <code>${waitSeconds - elapsed + 1}</code> 秒后自动刷新页面...（重启后需重新登录）`);
      return;
    }
    setVersionStatus("ok", `<strong>${head}</strong>，服务正在重启，正在自动重连...（重启后需重新登录）`);
    try {
      const res = await fetch("./api/app_version", { cache: "no-store" });
      if (res && res.status) {
        clearInterval(appReconnectTimer);
        appReconnectTimer = null;
        window.location.reload();
        return;
      }
    } catch (e) {}
    if (elapsed >= waitSeconds + giveUpAfter) {
      clearInterval(appReconnectTimer);
      appReconnectTimer = null;
      appUpdateRunning = false;
      setVersionStatus("warn", "服务重启时间较长，请手动刷新页面（重启后需要重新登录）。");
      $("version_check_btn").disabled = false;
    }
  }, 1000);
}

loadAppVersionQuick();

// 每 10 秒在前台空闲时自动更新节点与状态，无需手动刷新页面
setInterval(async () => {
  if (typeof state !== "undefined" && !state.is_connecting && (!testingNodeIds || !testingNodeIds.size) && document.visibilityState === "visible") {
    try {
      const r = await fetch("./api/nodes");
      const d = await r.json();
      nodes = d.nodes || [];
      state = d.state || {};
      stableSortNodes();
      updateCountryFilter();
      render();
    } catch(e) {}
  }
}, 10000);
let gatewayPollInterval = null;

function openGatewayModal() {
  $("admin_dropdown").style.display = "none";
  $("gateway_modal").style.display = "flex";
  loadGatewayStatus();
  if (gatewayPollInterval) clearInterval(gatewayPollInterval);
  gatewayPollInterval = setInterval(loadGatewayStatus, 3000);
}

function closeGatewayModal() {
  $("gateway_modal").style.display = "none";
  if (gatewayPollInterval) {
    clearInterval(gatewayPollInterval);
    gatewayPollInterval = null;
  }
}

async function loadGatewayStatus() {
  try {
    const res = await fetch("./api/gateway_status");
    const data = await res.json();
    if (data.ok && data.services) {
      renderGatewayServices(data.services);
    }
  } catch (e) {
    console.error("加载网关状态失败", e);
  }
}

function renderGatewayServices(services) {
  const container = $("gateway_services_list");
  if (!container) return;
  
  let html = "";
  services.forEach(s => {
    const statusText = s.status === "running" ? "正在运行" : "已停止";
    const badgeClass = s.status === "running" ? "available" : "unavailable";
    const statusPulse = s.status === "running" ? '<span class="badge-pulse"></span>' : '';
    
    html += `
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 10px; padding: 12px 16px; display: flex; flex-direction: column; gap: 6px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="font-size: 14px; color: var(--text-primary);">${esc(s.name)}</strong>
          <span class="badge ${badgeClass}">${statusPulse}${statusText}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-secondary);">${esc(s.details || "-")}</div>
        ${s.error ? `
          <div style="font-size: 12px; color: var(--danger); background: rgba(244,63,94,0.08); border: 1px solid rgba(244,63,94,0.15); border-radius: 6px; padding: 6px 10px; margin-top: 4px; line-height: 1.4;">
            诊断原因: ${esc(s.error)}
          </div>
        ` : ''}
      </div>
    `;
  });
  container.innerHTML = html;
}

let logsPollInterval = null;
let rawLogsCache = [];

function openLogsModal() {
  $("admin_dropdown").style.display = "none";
  $("logs_modal").style.display = "flex";
  loadLogs();
  if (logsPollInterval) clearInterval(logsPollInterval);
  logsPollInterval = setInterval(loadLogs, 2500);
}

function closeLogsModal() {
  $("logs_modal").style.display = "none";
  if (logsPollInterval) {
    clearInterval(logsPollInterval);
    logsPollInterval = null;
  }
}

async function loadLogs() {
  try {
    const res = await fetch("./api/logs");
    const data = await res.json();
    if (data.logs) {
      rawLogsCache = data.logs;
      filterAndRenderLogs();
    }
  } catch (e) {
    console.error("加载日志失败", e);
  }
}

function filterAndRenderLogs() {
  const filterVal = $("log_filter_select").value;
  const term = $("log_terminal_container");
  if (!term) return;
  
  let filtered = rawLogsCache;
  if (filterVal === "proxy") {
    filtered = rawLogsCache.filter(l => l.module === "Proxy");
  } else if (filterVal === "vpn") {
    filtered = rawLogsCache.filter(l => l.module === "VPN");
  } else if (filterVal === "system") {
    filtered = rawLogsCache.filter(l => !["Proxy", "VPN"].includes(l.module));
  }
  
  if (filtered.length === 0) {
    term.innerHTML = `<div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">暂无该类型日志。</div>`;
    return;
  }
  
  const linesHtml = filtered.map(l => {
    let color = "var(--log-default)";
    if (l.module === "Proxy") color = "var(--log-proxy)";
    if (l.module === "VPN") color = "var(--log-vpn)";
    if (l.level === "WARNING") color = "var(--log-warn)";
    if (l.level === "ERROR") color = "var(--log-error)";
    
    return `<div style="color: ${color}; margin-bottom: 4px;">[${esc(l.timestamp)}] [${esc(l.level)}] [${esc(l.module)}] ${esc(l.message)}</div>`;
  }).join("");
  
  const isAtBottom = term.scrollHeight - term.clientHeight <= term.scrollTop + 50;
  
  term.innerHTML = linesHtml;
  
  if (isAtBottom) {
    term.scrollTop = term.scrollHeight;
  }
}

function copyLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供复制的日志。");
    return;
  }
  
  navigator.clipboard.writeText(text).then(() => {
    alert("日志内容已成功复制到剪贴板！");
  }).catch(err => {
    console.error("复制失败", err);
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    alert("日志内容已复制到剪贴板！");
  });
}

function exportLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供导出的日志。");
    return;
  }
  
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const dateStr = new Date().toISOString().slice(0, 10);
  const filterVal = $("log_filter_select").value;
  a.download = `vpngate_log_${filterVal}_${dateStr}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function applyTheme(theme) {
  const light = theme === "light";
  document.documentElement.classList.toggle("light", light);
  if (document.body) document.body.classList.toggle("light", light);
}

function toggleTheme() {
  const next = document.documentElement.classList.contains("light") ? "dark" : "light";
  applyTheme(next);
  try { localStorage.setItem("theme", next); } catch (e) {}
}
</script>
</body></html>"""

def check_proxy_health() -> dict[str, Any]:
    # 1. 检测代理服务端口是否在监听
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(1.5)
        connect_host = LOCAL_PROXY_HOST
        if connect_host in ("::", "0.0.0.0", ""):
            connect_host = "::1" if is_ipv6 else "127.0.0.1"
        try:
            s.connect((connect_host, LOCAL_PROXY_PORT))
        except Exception as e:
            if connect_host == "::1":
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
            else:
                raise e
    except Exception as e:
        diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
        diag_msg = diag[1] if diag else f"端口 {LOCAL_PROXY_PORT} 连接失败，原因: {e}"
        return {
            "ok": False,
            "error": f"代理服务未运行 ({diag_msg})"
        }
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # 2. 检测虚拟网卡 tun0 是否存在 (Linux 下)
    tun_path = Path("/sys/class/net/tun0")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": "[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] VPN 虚拟网卡 (tun0) 未启用，请确保当前已成功连接 VPN 节点"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理接口测试 IP 与实际延迟
    def _curl_check_ip(url: str) -> dict[str, Any] | None:
        proxy_hosts = []
        if LOCAL_PROXY_HOST == "::":
            proxy_hosts = ["[::1]", "127.0.0.1"]
        elif LOCAL_PROXY_HOST == "0.0.0.0":
            proxy_hosts = ["127.0.0.1"]
        elif ":" in LOCAL_PROXY_HOST:
            proxy_hosts = [f"[{LOCAL_PROXY_HOST}]", "127.0.0.1"]
        else:
            proxy_hosts = [LOCAL_PROXY_HOST]

        for p_host in proxy_hosts:
            proxy_url = f"socks5h://{p_host}:{LOCAL_PROXY_PORT}"
            proxy_user, proxy_pass = proxy_server.get_proxy_credentials()
            cmd = [
                "curl", "-s",
                "-w", "\n%{time_total} %{http_code}",
                "-x", proxy_url,
                url,
                "--max-time", "5"
            ]
            if proxy_user is not None and proxy_pass is not None:
                cmd.extend(["--proxy-user", f"{proxy_user}:{proxy_pass}"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                if res.returncode == 0:
                    lines = res.stdout.strip().splitlines()
                    if len(lines) >= 2:
                        ip = lines[0].strip()
                        time_info = lines[1].strip().split()
                        if len(time_info) == 2:
                            total_time_str, http_code = time_info
                            if http_code == "200" and ip:
                                latency_ms = int(float(total_time_str) * 1000)
                                return {"ok": True, "ip": ip, "latency_ms": latency_ms}
            except Exception:
                pass
        return None

    try:
        result = _curl_check_ip("http://ip.sb")
        if result:
            return result
        result = _curl_check_ip("http://api.ipify.org")
        if result:
            return result
            
        # 此时外网测试失败，检测本地代理端口是否依然能连通。若仍能连通，直接抛出出口测试失败，不调用占用诊断
        port_still_listening = False
        test_sock = None
        try:
            test_sock = socket.socket(af, socket.SOCK_STREAM)
            test_sock.settimeout(1.0)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                test_sock.connect((connect_host, LOCAL_PROXY_PORT))
                port_still_listening = True
            except Exception:
                if connect_host == "::1":
                    test_sock.close()
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(1.0)
                    test_sock.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                    port_still_listening = True
        except Exception:
            pass
        finally:
            if test_sock is not None:
                try:
                    test_sock.close()
                except Exception:
                    pass

        if not port_still_listening:
            diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
            if diag:
                return {"ok": False, "error": f"出口连接测试失败 | 本机诊断结果: {diag[1]}"}
            
        return {"ok": False, "error": "出口连接测试失败 (ip.sb 和 api.ipify.org 均无法连通，可能是节点已失效或 VPS 防火墙限制了 UDP/TCP 出站端口)"}
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}

def background_proxy_checker() -> None:
    global last_checker_heartbeat, is_connecting
    time.sleep(30)
    while True:
        last_checker_heartbeat = time.time()
        try:
            if is_connecting:
                time.sleep(5)
                continue

            res = check_proxy_health()
            if res["ok"]:
                set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error=""
                )
                log_to_json("INFO", "Proxy", f"代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms")
            else:
                error_msg = res.get("error", "未知错误")
                if active_openvpn_node_id:
                    print(f"[警告] {LOCAL_PROXY_PORT} 端口本地代理当前不可用！原因: {error_msg}", flush=True)
                    log_to_json("WARNING", "Proxy", f"代理不可用: {error_msg}")
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=error_msg
                )

                # If we intended to have an active VPN node but proxy failed, trigger auto-switch
                if active_openvpn_node_id:
                    ui_cfg = load_ui_config()
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    if routing_mode != "fixed_ip":
                        with lock:
                            nodes = read_nodes()
                            active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                            if active_node:
                                mark_blacklisted(active_node, f"代理连通性检测失败: {error_msg}")
                                active_node["probe_status"] = "unavailable"
                                write_json(NODES_FILE, nodes)
                        auto_switch_node()
                    else:
                        print(f"[代理守护线程] 固定 IP 模式下代理不可用，正在尝试重启连接同一节点: {active_openvpn_node_id}", flush=True)
                        is_connecting = False
                        try:
                            connect_node(active_openvpn_node_id)
                        except Exception as e:
                            print(f"[代理守护线程] 重启固定节点失败: {e}", flush=True)
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(30)

def active_node_pinger() -> None:
    global last_pinger_heartbeat
    while True:
        last_pinger_heartbeat = time.time()
        try:
            if active_openvpn_running() and active_openvpn_node_id:
                nodes = read_nodes()
                node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if node:
                    ip = node.get("ip") or node.get("remote_host")
                    port = parse_int(node.get("remote_port"))
                    fallback = parse_int(node.get("ping"))
                    if ip:
                        latency = vpn_utils.ping_latency_ms(ip, port, fallback)
                        if latency > 0:
                            set_state(active_node_latency=f"{latency} ms")
                        else:
                            set_state(active_node_latency="检测超时")
                    else:
                        set_state(active_node_latency="检测超时")
                else:
                    set_state(active_node_latency="检测超时")
            elif is_connecting:
                set_state(active_node_latency="测试中...")
            else:
                set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)


# ───────────────────────── 网页端版本检查与在线更新 ─────────────────────────
# 与 `ml update` (install.sh update_service) 保持一致：
#   git fetch origin  ->  对比本地 HEAD 与 origin/<当前分支>  ->  git reset --hard origin/<分支>
#   ->  清理 __pycache__  ->  重启服务。
# 失败时只返回错误信息，绝不改动工作区。
APP_REPO_DIR: Path = ROOT_DIR
APP_GIT_TIMEOUT_SECONDS = 20.0
app_update_lock = threading.Lock()


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    # 后台更新不允许任何交互式输入（凭据、密码、host key 确认等）
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    askpass = shutil.which("true")
    if askpass:
        env["GIT_ASKPASS"] = askpass
    return env


def run_git(repo_dir: Path, args: list[str], timeout: float = APP_GIT_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    git_bin = shutil.which("git")
    if not git_bin:
        raise RuntimeError("服务器未安装 git 命令")
    cmd = [git_bin, "-c", f"safe.directory={repo_dir}", "-C", str(repo_dir), *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=_git_env(),
        stdin=subprocess.DEVNULL,
    )


def _git_output(repo_dir: Path, args: list[str], timeout: float = APP_GIT_TIMEOUT_SECONDS) -> str:
    proc = run_git(repo_dir, args, timeout=timeout)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(detail[:300] or f"git {' '.join(args)} 执行失败")
    return proc.stdout.strip()


def _resolve_repo_dir(repo_dir: Path | None = None) -> Path:
    return Path(repo_dir) if repo_dir else Path(APP_REPO_DIR)


def _is_git_repo(repo_dir: Path) -> bool:
    if not repo_dir.exists():
        return False
    try:
        proc = run_git(repo_dir, ["rev-parse", "--is-inside-work-tree"], timeout=8.0)
    except Exception:
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def _detect_branch(repo_dir: Path) -> str:
    branch = ""
    try:
        branch = _git_output(repo_dir, ["rev-parse", "--abbrev-ref", "HEAD"], timeout=8.0)
    except Exception:
        branch = ""
    if branch and branch != "HEAD":
        return branch
    # 与 install.sh 一致：分离 HEAD 时优先使用 origin/main、origin/master
    for candidate in ("main", "master"):
        for ref in (f"origin/{candidate}", candidate):
            try:
                if run_git(repo_dir, ["rev-parse", "--verify", "--quiet", ref], timeout=8.0).returncode == 0:
                    return candidate
            except Exception:
                continue
    return "main"


def _commit_meta(repo_dir: Path, ref: str) -> dict[str, str]:
    meta = {"commit": "", "commit_short": "", "date": "", "message": ""}
    try:
        raw = _git_output(repo_dir, ["log", "-1", "--format=%H%x1f%h%x1f%cI%x1f%s", ref], timeout=8.0)
    except Exception:
        return meta
    if not raw:
        return meta
    parts = (raw.split("\x1f") + ["", "", "", ""])[:4]
    meta["commit"] = parts[0].strip()
    meta["commit_short"] = parts[1].strip()
    meta["date"] = parts[2].strip()
    meta["message"] = parts[3].strip()
    return meta


def _worktree_dirty(repo_dir: Path) -> bool:
    try:
        proc = run_git(repo_dir, ["status", "--porcelain", "--untracked-files=no"], timeout=10.0)
    except Exception:
        return False
    return proc.returncode == 0 and bool(proc.stdout.strip())


def _clean_pycache(repo_dir: Path) -> None:
    # 与 install.sh 一致：更新后清理 Python 缓存，避免加载到旧的 .pyc
    try:
        for cache_dir in repo_dir.rglob("__pycache__"):
            if cache_dir.is_dir():
                shutil.rmtree(cache_dir, ignore_errors=True)
    except Exception as exc:
        print(f"[更新] 清理 __pycache__ 时出现问题: {exc}", flush=True)


def collect_app_version(check_remote: bool = False, repo_dir: Path | None = None) -> dict[str, Any]:
    """读取本地/远端版本信息。check_remote=True 时会执行 git fetch（只读，不修改工作区）。"""
    repo = _resolve_repo_dir(repo_dir)
    info: dict[str, Any] = {
        "ok": True,
        "git_available": shutil.which("git") is not None,
        "repo_path": str(repo),
        "is_git_repo": False,
        "branch": "",
        "current_commit": "",
        "current_commit_full": "",
        "current_date": "",
        "current_message": "",
        "remote_commit": "",
        "remote_commit_full": "",
        "remote_date": "",
        "remote_message": "",
        "commits_behind": 0,
        "commits_ahead": 0,
        "has_update": False,
        "checked_remote": False,
        "local_dirty": False,
        "updating": app_update_lock.locked(),
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "error": "",
    }
    if not info["git_available"]:
        info["ok"] = False
        info["error"] = "服务器未安装 git，无法检查或更新版本"
        return info
    if not _is_git_repo(repo):
        info["ok"] = False
        info["error"] = f"安装目录 {repo} 不是 Git 仓库，无法在线更新"
        return info
    try:
        info["is_git_repo"] = True
        branch = _detect_branch(repo)
        info["branch"] = branch
        local = _commit_meta(repo, "HEAD")
        info["current_commit"] = local["commit_short"]
        info["current_commit_full"] = local["commit"]
        info["current_date"] = local["date"]
        info["current_message"] = local["message"]
        info["local_dirty"] = _worktree_dirty(repo)

        if check_remote:
            try:
                fetch = run_git(repo, ["fetch", "--no-tags", "--prune", "origin"])
            except subprocess.TimeoutExpired:
                info["ok"] = False
                info["error"] = f"连接远端超时（超过 {int(APP_GIT_TIMEOUT_SECONDS)} 秒），请稍后重试"
                return info
            except Exception as exc:
                info["ok"] = False
                info["error"] = f"拉取远端版本信息失败: {exc}"
                return info
            if fetch.returncode != 0:
                detail = (fetch.stderr or fetch.stdout or "").strip().splitlines()
                info["ok"] = False
                info["error"] = "拉取远端版本信息失败: " + (detail[-1][:200] if detail else "网络不可用")
                return info
            remote_ref = f"origin/{branch}"
            remote = _commit_meta(repo, remote_ref)
            if not remote["commit"]:
                info["ok"] = False
                info["error"] = f"远端不存在分支 {remote_ref}"
                return info
            info["checked_remote"] = True
            info["remote_commit"] = remote["commit_short"]
            info["remote_commit_full"] = remote["commit"]
            info["remote_date"] = remote["date"]
            info["remote_message"] = remote["message"]
            try:
                behind = int(_git_output(repo, ["rev-list", "--count", f"HEAD..{remote_ref}"], timeout=10.0) or 0)
            except Exception:
                behind = 0
            try:
                ahead = int(_git_output(repo, ["rev-list", "--count", f"{remote_ref}..HEAD"], timeout=10.0) or 0)
            except Exception:
                ahead = 0
            info["commits_behind"] = max(behind, 0)
            info["commits_ahead"] = max(ahead, 0)
            info["has_update"] = info["commits_behind"] > 0
            info["diverged"] = info["has_update"] and info["commits_ahead"] > 0
    except Exception as exc:
        info["ok"] = False
        info["error"] = str(exc)
    return info


def perform_app_update(force: bool = False, repo_dir: Path | None = None) -> dict[str, Any]:
    """按 install.sh update_service() 的策略执行更新（fetch + reset --hard origin/<分支>）。

    只负责改动代码，不负责重启进程；重启由调用方（HTTP Handler）安排。
    """
    repo = _resolve_repo_dir(repo_dir)
    result: dict[str, Any] = {
        "ok": True,
        "updated": False,
        "restart_needed": False,
        "forced": bool(force),
        "needs_force": False,
        "branch": "",
        "old_commit": "",
        "new_commit": "",
        "old_message": "",
        "new_message": "",
        "old_date": "",
        "new_date": "",
        "commits_behind": 0,
        "message": "",
        "error": "",
    }
    if not shutil.which("git"):
        result["ok"] = False
        result["error"] = "服务器未安装 git，无法在线更新"
        return result
    if not _is_git_repo(repo):
        result["ok"] = False
        result["error"] = f"安装目录 {repo} 不是 Git 仓库，无法在线更新"
        return result
    try:
        branch = _detect_branch(repo)
        result["branch"] = branch
        old = _commit_meta(repo, "HEAD")
        result["old_commit"] = old["commit_short"]
        result["old_message"] = old["message"]
        result["old_date"] = old["date"]
        result["new_date"] = old["date"]

        try:
            fetch = run_git(repo, ["fetch", "--no-tags", "--prune", "origin"])
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"连接远端超时（超过 {int(APP_GIT_TIMEOUT_SECONDS)} 秒），请稍后重试")
        if fetch.returncode != 0:
            detail = (fetch.stderr or fetch.stdout or "").strip().splitlines()
            raise RuntimeError("拉取远端代码失败: " + (detail[-1][:200] if detail else "网络不可用"))

        remote_ref = f"origin/{branch}"
        remote = _commit_meta(repo, remote_ref)
        if not remote["commit"]:
            raise RuntimeError(f"远端不存在分支 {remote_ref}")
        try:
            behind = int(_git_output(repo, ["rev-list", "--count", f"HEAD..{remote_ref}"], timeout=10.0) or 0)
        except Exception:
            behind = 0
        result["commits_behind"] = max(behind, 0)
        result["new_message"] = remote["message"]
        result["new_date"] = remote["date"]

        if not force:
            if behind <= 0 and old["commit"] == remote["commit"]:
                result["new_commit"] = old["commit_short"]
                result["message"] = "当前已是最新版本"
                return result
            if behind <= 0:
                result["ok"] = False
                result["needs_force"] = True
                result["new_commit"] = remote["commit_short"]
                result["message"] = "本地代码与远端不一致（可能包含本地改动或领先的提交），如需强制对齐请使用强制更新"
                return result

        log_to_json(
            "INFO",
            "Main",
            f"开始在线更新：{branch} {old['commit_short'] or '?'} -> {remote['commit_short']}（落后 {result['commits_behind']} 个提交）",
        )
        reset = run_git(repo, ["reset", "--hard", "--quiet", remote_ref], timeout=60.0)
        if reset.returncode != 0:
            detail = (reset.stderr or reset.stdout or "").strip().splitlines()
            raise RuntimeError("应用远端代码失败: " + (detail[-1][:200] if detail else "未知错误"))

        _clean_pycache(repo)
        new = _commit_meta(repo, "HEAD")
        result["new_commit"] = new["commit_short"]
        result["new_message"] = new["message"]
        result["new_date"] = new["date"]
        result["updated"] = True
        result["restart_needed"] = True
        if old["commit"] == new["commit"]:
            result["message"] = "已强制重新拉取代码（版本未变化），服务将在 2 秒内自动重启..."
        else:
            result["message"] = f"更新成功（{result['commits_behind']} 个新提交），服务将在 2 秒内自动重启..."
        log_to_json(
            "INFO",
            "Main",
            f"在线更新完成：{branch} {old['commit_short'] or '?'} -> {new['commit_short'] or '?'}，即将重启服务",
        )
    except Exception as exc:
        result["ok"] = False
        result["error"] = str(exc)
        log_to_json("ERROR", "Main", f"在线更新失败: {exc}")
    return result


def service_restart_command() -> list[str] | None:
    systemctl = shutil.which("systemctl")
    if systemctl:
        for unit in (
            "/lib/systemd/system/aimilivpn.service",
            "/etc/systemd/system/aimilivpn.service",
            "/usr/lib/systemd/system/aimilivpn.service",
        ):
            if Path(unit).exists():
                return [systemctl, "restart", "aimilivpn.service"]
    rc_service = shutil.which("rc-service")
    if rc_service and Path("/etc/init.d/aimilivpn").exists():
        return [rc_service, "aimilivpn", "restart"]
    return None


def _exit_process() -> None:
    """进程退出（独立函数便于测试与以后改为其他重启方式）。"""
    os._exit(0)


def schedule_app_restart(reason: str = "代码已更新", delay: float = 2.0) -> None:
    """延后重启进程，让 HTTP 响应先回到浏览器（与 update_settings / update_credentials 相同的方式）。"""
    def _worker() -> None:
        time.sleep(delay)
        cmd = service_restart_command()
        if cmd:
            try:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                print(f"[系统] {reason}，已请求重启服务: {' '.join(cmd)}", flush=True)
                # 服务管理器应在数秒内结束本进程；若长时间未接管（未启用自动重启），主动退出兜底
                time.sleep(20)
                print(f"[系统] {reason}，进程仍未退出，主动退出以触发自动重启...", flush=True)
                _exit_process()
                return
            except Exception as exc:
                print(f"[警告] 重启服务命令执行失败: {exc}", flush=True)
        print(f"[系统] {reason}，进程即将退出以触发自动重启...", flush=True)
        _exit_process()

    threading.Thread(target=_worker, daemon=True, name="app-restart").start()


class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        ui_cfg = load_ui_config()
        return ui_cfg.get("secret_path", "EJsW2EeBo9lY")

    def is_authorized(self) -> bool:
        ui_cfg = load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            print("[Auth] 管理后台密码为空，已拒绝访问。请检查 ui_auth.json。", flush=True)
            return False
        
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
        
        session_token = cookies.get("session")
        if not session_token:
            return False
            
        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        request_path = urllib.parse.urlsplit(self.path).path
        if not secret_path:
            return request_path
        if request_path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if request_path.startswith(prefix):
            return "/" + request_path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def read_request_body(self, max_bytes: int = 65536) -> bytes:
        length = parse_int(self.headers.get("Content-Length"))
        if length < 0:
            raise ValueError("Content-Length 无效")
        if length > max_bytes:
            raise ValueError(f"请求体过大，最大允许 {max_bytes} 字节")
        return self.rfile.read(length) if length > 0 else b""

    def read_json_body(self, max_bytes: int = 65536) -> dict[str, Any]:
        body = self.read_request_body(max_bytes)
        if not body:
            return {}
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("请求 JSON 必须是对象")
        return data

    def do_GET(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
                
        if effective_path in ("/", "/index.html"):
            self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif effective_path == "/api/nodes":
            global last_active_ping_time, last_active_latency, active_openvpn_node_id
            nodes = read_nodes()
            active_node = next((n for n in nodes if active_openvpn_node_id and n.get("id") == active_openvpn_node_id), None)
            for n in nodes:
                n["active"] = (active_openvpn_node_id and n.get("id") == active_openvpn_node_id)
            if active_node:
                ip = active_node.get("ip") or active_node.get("remote_host")
                if ip:
                    now = time.time()
                    if now - last_active_ping_time > 15.0:
                        last_active_ping_time = now
                        def bg_ping(ip_addr: str, port: int, fallback: int) -> None:
                            global last_active_latency
                            try:
                                latency = vpn_utils.ping_latency_ms(ip_addr, port, fallback)
                                if latency > 0:
                                    last_active_latency = latency
                            except Exception:
                                pass
                        threading.Thread(
                            target=bg_ping, 
                            args=(ip, parse_int(active_node.get("remote_port")), parse_int(active_node.get("ping"))),
                            daemon=True
                        ).start()
                    if last_active_latency > 0:
                        active_node["latency_ms"] = last_active_latency
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped_nodes.append(stripped)
            self.send_json({"nodes": stripped_nodes, "state": get_state()})
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_nodes()
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        elif effective_path == "/api/gateway_status":
            web_ui_status = {
                "name": "Web 管理服务",
                "status": "running",
                "details": f"监听地址: {load_ui_config().get('host', UI_HOST)}:{load_ui_config().get('port', UI_PORT)}",
                "error": ""
            }
            proxy_ok = False
            proxy_err = ""
            is_ipv6 = ":" in LOCAL_PROXY_HOST
            af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            s = None
            try:
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(0.5)
                connect_host = LOCAL_PROXY_HOST
                if connect_host in ("::", "0.0.0.0", ""):
                    connect_host = "::1" if is_ipv6 else "127.0.0.1"
                try:
                    s.connect((connect_host, LOCAL_PROXY_PORT))
                    proxy_ok = True
                except Exception:
                    if connect_host == "::1":
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        proxy_ok = True
                    else:
                        raise
            except Exception as e:
                diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
                proxy_err = diag[1] if diag else f"本地代理网关无法连通: {e}"
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
            proxy_gateway_status = {
                "name": "本地代理网关",
                "status": "running" if proxy_ok else "stopped",
                "details": f"监听地址: {LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
                "error": proxy_err
            }
            ovpn_ok = active_openvpn_running()
            ovpn_err = ""
            ovpn_details = "未连接"
            if ovpn_ok:
                ovpn_details = f"已连接节点: {active_openvpn_node_id}"
                if sys.platform.startswith("linux"):
                    if not Path("/sys/class/net/tun0").exists():
                        ovpn_err = "[警告] 虚拟网卡 (tun0) 未启用，可能存在策略路由配置问题。"
            else:
                if active_openvpn_node_id:
                    ovpn_err = "连接已中断或 OpenVPN 核心程序异常退出。"
                    ovpn_details = f"尝试连接节点 {active_openvpn_node_id} 失败"
            openvpn_status = {
                "name": "OpenVPN 核心连接",
                "status": "running" if ovpn_ok else "stopped",
                "details": ovpn_details,
                "error": ovpn_err
            }
            now = time.time()
            server_uptime = now - server_start_time
            collector_ok = (last_collector_heartbeat > 0.0 and now - last_collector_heartbeat < (CHECK_INTERVAL_SECONDS * 1.5)) or (server_uptime < 15.0)
            collector_status = {
                "name": "节点同步守护线程",
                "status": "running" if collector_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_collector_heartbeat)) if last_collector_heartbeat > 0 else '等待启动'}",
                "error": "" if collector_ok else "线程可能已异常终止，导致无法在后台拉取和测速新节点。"
            }
            checker_ok = (last_checker_heartbeat > 0.0 and now - last_checker_heartbeat < 90.0) or (server_uptime < 35.0)
            checker_status = {
                "name": "出口检测守护线程",
                "status": "running" if checker_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_checker_heartbeat)) if last_checker_heartbeat > 0 else '等待启动'}",
                "error": "" if checker_ok else "线程可能已挂起或终止，导致无法实时获取代理出口状态。"
            }
            pinger_ok = (last_pinger_heartbeat > 0.0 and now - last_pinger_heartbeat < 30.0) or (server_uptime < 15.0)
            pinger_status = {
                "name": "延迟测速守护线程",
                "status": "running" if pinger_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pinger_heartbeat)) if last_pinger_heartbeat > 0 else '等待启动'}",
                "error": "" if pinger_ok else "线程可能已中止，无法实时刷新活动节点的 Ping 延迟。"
            }
            self.send_json({
                "ok": True,
                "services": [
                    web_ui_status,
                    proxy_gateway_status,
                    openvpn_status,
                    collector_status,
                    checker_status,
                    pinger_status
                ]
            })
        elif effective_path == "/api/logs":
            logs_dir = DATA_DIR / "logs"
            date_str = time.strftime("%Y-%m-%d", time.localtime())
            log_file = logs_dir / f"{date_str}.json"
            entries = []
            if log_file.exists():
                try:
                    with lock:
                        with open(log_file, "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    try:
                                        entries.append(json.loads(line))
                                    except Exception:
                                        pass
                except Exception as e:
                    print(f"[API Logs] Error reading log file: {e}", flush=True)
            self.send_json({"logs": entries})
        elif effective_path == "/api/app_version":
            try:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query, keep_blank_values=True)
                check = str((query.get("check") or [""])[0]).strip().lower() in ("1", "true", "yes", "on")
                self.send_json(collect_app_version(check_remote=check))
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if effective_path == "/api/login":
            try:
                payload = self.read_json_body()
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")
                
                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")
                
                if expected_pwd and input_pwd == expected_pwd and input_uname == expected_uname:
                    token = uuid.uuid4().hex
                    with lock:
                        active_sessions[token] = time.time() + 30 * 24 * 3600
                    body = json.dumps({"ok": True}).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    secret_path = self.get_secret_path()
                    cookie_path = f"/{secret_path}/" if secret_path else "/"
                    self.send_header("Set-Cookie", f"session={token}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_json({"ok": False, "error": "用户名或密码不正确，请重新输入"}, HTTPStatus.FORBIDDEN)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    with lock:
                        active_sessions.pop(session_token, None)
                secret_path = self.get_secret_path()
                cookie_path = f"/{secret_path}/" if secret_path else "/"
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", f"session=; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if effective_path == "/api/update_credentials":
            try:
                payload = self.read_json_body()
                new_username = str(payload.get("username") or "").strip()
                new_password = str(payload.get("password") or "").strip()
                new_port = payload.get("port")
                new_suffix = str(payload.get("secret_path") or "").strip()
                
                ui_cfg = load_ui_config()
                if not new_username or (not new_password and not ui_cfg.get("password")):
                    self.send_json({"ok": False, "error": "用户名不能为空；首次设置时密码不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                
                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "网页管理端口范围必须是 1 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return

                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return

                expected_username = ui_cfg.get("username", "")
                expected_password = ui_cfg.get("password", "")
                expected_port = ui_cfg.get("port", 8787)
                expected_suffix = ui_cfg.get("secret_path", "EJsW2EeBo9lY")

                ui_cfg["username"] = new_username
                if new_password:
                    ui_cfg["password"] = new_password
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix
                
                auth_file = DATA_DIR / "ui_auth.json"
                reauth_required = new_username != expected_username or (new_password and new_password != expected_password)
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                    if reauth_required:
                        active_sessions.clear()
                
                restart_needed = (new_port_int != expected_port or new_suffix != expected_suffix)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "reauth_required": reauth_required, "message": "配置更新成功，网页管理端口或路径已变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 管理后台安全配置更新，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    self.send_json({"ok": True, "restart_needed": False, "reauth_required": reauth_required, "message": "账号密码配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_settings":
            try:
                payload = self.read_json_body()
                
                new_proxy_port = payload.get("proxy_port")
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                
                try:
                    new_proxy_port_int = int(new_proxy_port)
                    if not (1024 <= new_proxy_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "代理出站端口范围必须是 1024 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                expected_proxy_port = ui_cfg.get("proxy_port", 7928)
                
                if new_proxy_port_int == ui_cfg.get("port", 8787):
                    self.send_json({"ok": False, "error": "代理出站端口不能与网页管理端口相同"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg["proxy_port"] = new_proxy_port_int
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                restart_needed = (new_proxy_port_int != expected_proxy_port)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "message": "配置更新成功，代理出站端口变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 代理出站端口变更，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    self.send_json({"ok": True, "restart_needed": False, "message": "配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_routing":
            try:
                payload = self.read_json_body()
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                fav_fail_fallback = bool(payload.get("fav_fail_fallback", True))
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                ui_cfg["fav_fail_fallback"] = fav_fail_fallback
                ui_cfg.pop("enable_force_country", None)
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                self.send_json({"ok": True, "message": "出站路由配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/toggle_favorite":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "").strip()
                
                ui_cfg = load_ui_config()
                fav_ids = ui_cfg.get("favorite_node_ids", [])
                if not isinstance(fav_ids, list):
                    fav_ids = []
                
                if node_id in fav_ids:
                    fav_ids.remove(node_id)
                else:
                    fav_ids.append(node_id)
                
                ui_cfg["favorite_node_ids"] = fav_ids
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                self.send_json({"ok": True, "favorite_node_ids": fav_ids})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/update_app":
            try:
                payload = self.read_json_body()
                force = bool(payload.get("force"))
                if not app_update_lock.acquire(blocking=False):
                    self.send_json({"ok": False, "error": "已有更新任务正在进行，请稍后再试"}, HTTPStatus.CONFLICT)
                    return
                try:
                    result = perform_app_update(force=force)
                finally:
                    app_update_lock.release()
                if result.get("ok") and result.get("updated"):
                    # 先把结果送回浏览器，再延后重启，避免响应被中断
                    self.send_json(result)
                    schedule_app_restart(
                        reason=f"代码已更新 {result.get('old_commit') or '?'} -> {result.get('new_commit') or '?'}",
                        delay=2.0,
                    )
                else:
                    status = HTTPStatus.OK if result.get("ok") or result.get("needs_force") else HTTPStatus.BAD_REQUEST
                    self.send_json(result, status)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                self.send_json({"ok": True, "message": maintain_valid_nodes(force=True)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                if maintenance_lock.locked():
                    self.send_json({"ok": True, "message": "节点维护任务正在运行，请稍后再试", "running": True})
                else:
                    threading.Thread(target=maintain_valid_nodes, args=(False,), daemon=True).start()
                    self.send_json({"ok": True, "message": "已在后台启动节点更新流程", "running": False})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes":
            try:
                payload = self.read_json_body(max_bytes=262144)
                node_ids = payload.get("ids", [])
                tested_nodes = test_multiple_nodes(node_ids)
                self.send_json({"ok": True, "nodes": tested_nodes})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                ui_cfg = load_ui_config()
                ui_cfg["connection_enabled"] = False
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                stop_active_openvpn()
                with lock:
                    nodes = read_nodes()
                    for item in nodes:
                        item["active"] = False
                    write_json(NODES_FILE, nodes)
                global last_active_ping_time, last_active_latency
                last_active_ping_time = 0.0
                last_active_latency = 0
                set_state(active_openvpn_node_id="", last_check_message="手动断开连接", active_node_latency="无活动连接")
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect":
            try:
                payload = self.read_json_body()
                self.send_json({"ok": True, "message": connect_node(str(payload.get("id") or ""))})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_node":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "")
                updated_node = test_node_by_id(node_id)
                self.send_json({"ok": True, "node": updated_node})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                self.read_request_body()
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

    def isatty(self) -> bool:
        return self.stdout.isatty()

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.stdout, attr)

def main() -> None:
    ensure_dirs()
    kill_existing_openvpn_processes()
    
    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "target_valid_nodes": TARGET_VALID_NODES,
            "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "local_proxy": f"http://{'[' + LOCAL_PROXY_HOST + ']' if ':' in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
            "active_openvpn_node_id": "",
            "last_fetch_status": "starting",
            "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
            "is_connecting": True,
            "active_node_latency": "正在准备",
            "blacklisted_nodes": 0,
        },
    )
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()
    
    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    for _ in range(30):
        s = None
        try:
            s = socket.socket(af, socket.SOCK_STREAM)
            s.settimeout(0.5)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                s.connect((connect_host, LOCAL_PROXY_PORT))
                gateway_ready = True
                break
            except Exception:
                if connect_host == "::1":
                    try:
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        gateway_ready = True
                        break
                    except Exception:
                        pass
                raise
        except Exception:
            time.sleep(0.5)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            
    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)

    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    threading.Thread(target=active_node_pinger, daemon=True).start()
    
    ui_cfg = load_ui_config()
    ui_host = ui_cfg.get("host", UI_HOST)
    ui_port = bounded_int(ui_cfg.get("port"), UI_PORT, 1, 65535)
    
    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}", flush=True)
    DualStackHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    main()
