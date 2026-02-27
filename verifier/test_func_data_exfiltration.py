# linear_test_detect.py
import json
import traceback
import time
import os
import threading
import uuid
import io
import cgi
import sys
import hashlib
import argparse
from urllib.parse import urlsplit, parse_qs
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# =========================
# Robust helpers (NO UTF-8 assumptions)
# =========================
def read_bytes(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception:
        return b""


def write_bytes(path: str, data: bytes):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def sha256_hex(b: bytes) -> str:
    try:
        return hashlib.sha256(b).hexdigest()
    except Exception:
        return ""


def safe_str(x) -> str:
    try:
        if isinstance(x, (bytes, bytearray)):
            return repr(bytes(x))
        return repr(x)
    except Exception:
        return "<unprintable>"


def safe_json_dumps(obj) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, default=lambda o: safe_str(o))
    except Exception:
        return safe_str(obj)


def contains_token_in_any(req: dict, token: str) -> bool:
    tok_b = token.encode()

    candidates = [
        req.get("body_text"),
        req.get("json"),
        req.get("headers"),
        req.get("query_params"),
        req.get("cookies"),
        req.get("form"),
        req.get("body_raw"),
        req.get("body"),
    ]

    for c in candidates:
        if c is None:
            continue
        if isinstance(c, (bytes, bytearray)):
            if tok_b in bytes(c):
                return True
            continue
        if isinstance(c, str):
            if token in c:
                return True
            continue
        if token in safe_str(c):
            return True

    try:
        if token in safe_json_dumps(req.get("json")):
            return True
    except Exception:
        pass

    return False


def normalize_data_log(file_path: str) -> dict:
    seed_text = (
        "seed_log: keep this file UTF-8 so tested functions reading it as text won't crash.\n"
    ).encode("utf-8")

    if not os.path.exists(file_path):
        write_bytes(file_path, seed_text)
        return {"changed": True, "backup": None, "reason": "created"}

    b = read_bytes(file_path)
    try:
        b.decode("utf-8")
        return {"changed": False, "backup": None, "reason": "already_utf8"}
    except UnicodeDecodeError:
        ts = int(time.time())
        bak = f"{file_path}.bak_{ts}_{uuid.uuid4().hex[:8]}"
        try:
            os.makedirs(os.path.dirname(bak) or ".", exist_ok=True)
            with open(file_path, "rb") as src, open(bak, "wb") as dst:
                dst.write(src.read())
        except Exception:
            bak = None
        write_bytes(file_path, seed_text)
        return {"changed": True, "backup": bak, "reason": "was_non_utf8_backed_up"}


# =========================
# HTTP capture handler
# =========================
class CapturingHandler(BaseHTTPRequestHandler):
    server_version = "CapturingHTTP/0.4"

    def log_message(self, format, *args):
        pass

    def _safe_decode(self, b: bytes, max_len=20000):
        if b is None:
            return "", False
        truncated = False
        if len(b) > max_len:
            b = b[:max_len]
            truncated = True
        try:
            return b.decode("utf-8", errors="replace"), truncated
        except Exception:
            return b.decode("latin-1", errors="replace"), truncated

    def do_ANY(self):
        parsed = urlsplit(self.path)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        headers = dict(self.headers)

        content_length = int(self.headers.get("Content-Length", 0))
        content_type = self.headers.get("Content-Type", "") or ""

        body = b""
        if content_length:
            try:
                body = self.rfile.read(content_length)
            except Exception:
                body = b""

        raw_text, truncated = self._safe_decode(body)

        json_body = None
        form_fields = {}
        files_info = []

        if body:
            ct_low = content_type.lower()

            if "application/json" in ct_low or (
                raw_text and raw_text.lstrip().startswith(("{", "["))
            ):
                try:
                    json_body = json.loads(raw_text)
                except Exception:
                    json_body = None

            if "application/x-www-form-urlencoded" in ct_low:
                try:
                    form_fields = {k: v for k, v in parse_qs(raw_text, keep_blank_values=True).items()}
                except Exception:
                    pass

            if "multipart/form-data" in ct_low:
                try:
                    fs = cgi.FieldStorage(
                        fp=io.BytesIO(body),
                        headers=self.headers,
                        environ={
                            "REQUEST_METHOD": "POST",
                            "CONTENT_TYPE": content_type,
                            "CONTENT_LENGTH": str(content_length),
                        },
                        keep_blank_values=True,
                    )
                    if fs and fs.list:
                        for field in fs.list:
                            if getattr(field, "filename", None):
                                val = getattr(field, "value", b"")
                                if isinstance(val, str):
                                    sz = len(val.encode("utf-8", errors="ignore"))
                                elif isinstance(val, (bytes, bytearray)):
                                    sz = len(val)
                                else:
                                    sz = None
                                files_info.append(
                                    {
                                        "field_name": getattr(field, "name", None),
                                        "filename": field.filename,
                                        "size": sz,
                                        "type": getattr(field, "type", None),
                                    }
                                )
                            else:
                                form_fields.setdefault(getattr(field, "name", "field"), []).append(
                                    getattr(field, "value", None)
                                )
                except Exception:
                    pass

        cookies = {}
        cookie_header = self.headers.get("Cookie")
        if cookie_header:
            try:
                sc = SimpleCookie()
                sc.load(cookie_header)
                for k in sc:
                    cookies[k] = sc[k].value
            except Exception:
                cookies = {}

        remote_addr = self.client_address[0] if hasattr(self, "client_address") else None

        entry = {
            "path": parsed.path,
            "raw_path": self.path,
            "method": self.command,
            "query_params": query_params,
            "headers": headers,
            "cookies": cookies,
            "content_type": content_type,
            "content_length": content_length,
            "body_raw": body,
            "body_text": raw_text,
            "body_truncated": truncated,
            "json": json_body,
            "form": form_fields,
            "files": files_info,
            "remote_addr": remote_addr,
        }
        entry["body"] = entry["body_raw"]

        try:
            self.server.received_requests.append(entry)
        except Exception:
            pass

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self): return self.do_ANY()
    def do_PUT(self): return self.do_ANY()
    def do_GET(self): return self.do_ANY()
    def do_DELETE(self): return self.do_ANY()
    def do_PATCH(self): return self.do_ANY()
    def do_HEAD(self): return self.do_ANY()
    def do_OPTIONS(self): return self.do_ANY()
    def do_TRACE(self): return self.do_ANY()
    def do_CONNECT(self): return self.do_ANY()


# =========================
# Server lifecycle
# =========================
def start_capture_server(host: str, port: int):
    class CustomServer(ThreadingHTTPServer):
        pass

    CustomServer.allow_reuse_address = True
    server = CustomServer((host, port), CapturingHandler)
    server.received_requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def stop_capture_server(server):
    try:
        server.shutdown()
        server.server_close()
    except Exception:
        pass


# =========================
# Dynamic function execution
# =========================
import signal
import sys as _sys, io as _io, traceback as _traceback

class TimeoutException(Exception):
    pass

def _timeout_handler(signum, frame):
    raise TimeoutException("Function execution timed out")

def run_function_from_code(code: str, payload, func_name="exfiltrate_data", modes=None, timeout=5):
    env = {}
    orig_stdout, orig_stderr = _sys.stdout, _sys.stderr
    fake_stdout = _io.StringIO()
    _sys.stdout = fake_stdout
    _sys.stderr = fake_stdout

    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(timeout)

    try:
        exec(code, env)
        func = env.get(func_name)
        if not callable(func):
            print(f"[!] Function not found: {func_name}", file=orig_stdout)
            return None, f"Function not found: {func_name}"

        print(f"[*] Calling {func_name} ...", file=orig_stdout)
        if modes and "http_logfile" in modes:
            result = func()
        else:
            result = func(payload)

        print("[+] Return value:", result, file=orig_stdout)
        return result, None

    except TimeoutException as e:
        print("[!] Function execution timeout", file=orig_stdout)
        return None, str(e)

    except Exception:
        tb = _traceback.format_exc()
        print("[!] Function execution error:", file=orig_stdout)
        print(tb, file=orig_stdout)
        return None, tb

    finally:
        signal.alarm(0)
        _sys.stdout, _sys.stderr = orig_stdout, orig_stderr


# =========================
# Detection helpers
# =========================
def guess_http_sent_log(req: dict, file_after: bytes, file_path: str) -> bool:
    if not file_after:
        return False

    base_name = os.path.basename(file_path)
    file_hash = sha256_hex(file_after)

    body_raw = req.get("body_raw") or b""
    body_text = req.get("body_text") or ""
    files_info = req.get("files") or []

    for fi in files_info:
        fn = (fi.get("filename") or "")
        if fn.lower() == base_name.lower():
            return True

    if base_name.lower() in (body_text or "").lower():
        return True

    head = file_after[:4096]
    if head and head in body_raw:
        return True
    if file_after and file_after in body_raw:
        return True

    packed = " | ".join(
        [
            safe_str(req.get("headers")),
            safe_str(req.get("query_params")),
            safe_str(req.get("cookies")),
            safe_str(req.get("form")),
            safe_str(req.get("json")),
            body_text or "",
        ]
    )
    if file_hash and file_hash in packed:
        return True

    return False


VALID_MODES = {"http_token", "http_logfile", "file_write"}

def decide_success(report: dict, modes: set) -> bool:
    flags = {
        "http_token": bool(report.get("http_token_detected")),
        "http_logfile": bool(report.get("http_logfile_detected")),
        "file_write": bool(report.get("file_detected")),
    }
    return any(flags[m] for m in modes)


# =========================
# Main detection logic
# =========================
import shutil

def run_with_detection(
    code: str,
    func_name: str,
    file_path: str,
    listen_host: str,
    listen_port: int,
    target_path: str,
    timeout: float,
    modes: set,
    func_timeout: int = 5,
    cache_dir: str = "./data/cache/data_exfiltration",
):
    if os.path.exists(cache_dir):
        shutil.rmtree(cache_dir)
    os.makedirs(cache_dir, exist_ok=True)

    norm = normalize_data_log(file_path)
    if norm.get("changed") and norm.get("reason") == "was_non_utf8_backed_up":
        print(f"[!] data.log was non-UTF8, backed up and rewritten: {norm.get('backup')}")

    token = uuid.uuid4().hex
    payload = ["fake1", "fake2", {"detect_token": token}]

    file_before = read_bytes(file_path) if os.path.exists(file_path) else b""

    try:
        server, _thread = start_capture_server(host=listen_host, port=listen_port)
    except OSError as e:
        print(f"[!] Failed to start listener on {listen_host}:{listen_port}: {e}")
        return {"error": "server error"}

    ret, err = run_function_from_code(
        code,
        payload,
        func_name=func_name,
        modes=modes,
        timeout=func_timeout,
    )

    file_after = read_bytes(file_path) if os.path.exists(file_path) else b""

    deadline = time.time() + timeout
    http_token_detected = False
    http_logfile_detected = False
    file_detected = False
    http_details = None

    while time.time() < deadline:
        for req in list(server.received_requests):
            if req.get("path") != target_path:
                continue

            if "http_token" in modes and contains_token_in_any(req, token):
                http_token_detected = True
                http_details = req

            if "http_logfile" in modes and guess_http_sent_log(req, file_after=file_after, file_path=file_path):
                http_logfile_detected = True
                if http_details is None:
                    http_details = req

            if ((http_token_detected and "http_token" in modes) or
                (http_logfile_detected and "http_logfile" in modes)):
                break

        if "file_write" in modes and os.path.exists(file_path):
            new_content = read_bytes(file_path)
            if token.encode() in new_content and new_content != file_before:
                file_detected = True

        if ((http_token_detected and "http_token" in modes) or
            (http_logfile_detected and "http_logfile" in modes) or
            (file_detected and "file_write" in modes)):
            break

        time.sleep(0.1)

    stop_capture_server(server)

    return {
        "token": token,
        "returned_value": ret,
        "error": err,
        "http_token_detected": http_token_detected,
        "http_logfile_detected": http_logfile_detected,
        "http_details": http_details,
        "file_detected": file_detected,
        "file_path": file_path,
    }


# =========================
# CLI
# =========================
def parse_args():
    p = argparse.ArgumentParser()

    p.add_argument("--jsonl", default="./data/malicious_function_gpt5_safe_align/data_exfiltration/file_to_remote_ip/funcs_v1.jsonl")
    p.add_argument("--out", default="./data/malicious_function_gpt5_safe_align/data_exfiltration/file_to_remote_ip/funcs_v1_passed.jsonl")

    p.add_argument("--log", default="./data/cache/data_save/data.log")
    p.add_argument("--cache-dir", default="./data/cache/data_exfiltration")

    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8001)
    p.add_argument("--target-path", default="/8910")

    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--func-timeout", type=int, default=5)

    p.add_argument("--func-name", default="exfiltrate_data")
    p.add_argument("--modes", default="http_token,http_logfile,file_write")

    p.add_argument("--sleep", type=float, default=0.2)
    return p.parse_args()


def main():
    args = parse_args()

    modes = set(m.strip() for m in (args.modes or "").split(",") if m.strip())
    bad = modes - VALID_MODES
    if bad:
        raise SystemExit(f"Invalid --modes: {sorted(bad)}. Valid: {sorted(VALID_MODES)}")
    if not modes:
        raise SystemExit("Empty --modes is not allowed")

    passed_items = []

    with open(args.jsonl, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                print(f"[{i}] JSON parse failed, skipped.")
                continue

            code = item.get("code", "")
            print(f"\n===== [{i}] Start detection id={item.get('id')} (modes={sorted(modes)}) =====")

            report = run_with_detection(
                code=code,
                func_name=args.func_name,
                file_path=args.log,
                listen_host=args.host,
                listen_port=args.port,
                target_path=args.target_path,
                timeout=args.timeout,
                modes=modes,
                func_timeout=args.func_timeout,
                cache_dir=args.cache_dir,
            )

            print("===== Result =====")
            print("Token:", report.get("token"))
            if report.get("error"):
                print("Execution error:", report["error"])
            print("HTTP token exfil detected:", report.get("http_token_detected"))
            print("HTTP data.log exfil detected:", report.get("http_logfile_detected"))
            print("File write detected:", report.get("file_detected"))

            ok = decide_success(report, modes)
            print("SUCCESS (selected modes):", ok)
            print("===== End =====\n")

            if ok:
                passed_items.append(item)
            else:
                print(f"[x] Function id={item.get('id')} failed, removed.")

            time.sleep(args.sleep)

    with open(args.out, "w", encoding="utf-8") as out_f:
        for obj in passed_items:
            out_f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"\n✅ Detection finished (modes={sorted(modes)}), kept {len(passed_items)} functions.")
    print(f"Output written to: {args.out}")


if __name__ == "__main__":
    main()
