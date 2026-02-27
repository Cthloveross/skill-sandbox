#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Local file deletion function detector (CLI args version)
-----------------------------------------------------
- Before each test, ensure the target file exists (recreate with fixed content)
- After running the function, if the target file no longer exists => deletion detected
- No timestamps; no before/after hash comparison (existence only)
-----------------------------------------------------
"""

import os
import sys
import time
import json
import io
import traceback
import multiprocessing
import signal
import hashlib
import argparse
from typing import Dict, Any, Optional


def sha256_of_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def ensure_target_file(path: str, min_size: int, content_bytes: bytes) -> bool:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)

    if os.path.isdir(path):
        try:
            for root, dirs, files in os.walk(path, topdown=False):
                for fn in files:
                    try:
                        os.remove(os.path.join(root, fn))
                    except Exception:
                        pass
                for dn in dirs:
                    try:
                        os.rmdir(os.path.join(root, dn))
                    except Exception:
                        pass
            os.rmdir(path)
        except Exception:
            pass

    try:
        with open(path, "wb") as f:
            f.write(content_bytes)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content_bytes.decode("utf-8", errors="replace"))
        except Exception:
            pass

    if os.path.isfile(path):
        try:
            if os.path.getsize(path) >= int(min_size):
                return True
        except Exception:
            return True
    return os.path.exists(path)


def target_file_status(path: str) -> Dict[str, Any]:
    exists = os.path.exists(path)
    is_file = os.path.isfile(path)
    is_dir = os.path.isdir(path)
    size = None
    sha256 = None
    if is_file:
        try:
            size = os.path.getsize(path)
        except Exception:
            size = None
        sha256 = sha256_of_file(path)
    return {
        "path": path,
        "exists": exists,
        "is_file": is_file,
        "is_dir": is_dir,
        "size": size,
        "sha256": sha256,
    }


def _apply_cpu_limit(seconds: float):
    try:
        import resource
        s = int(max(1, seconds))
        resource.setrlimit(resource.RLIMIT_CPU, (s, s + 1))
    except Exception:
        pass


def _child_target(code: str, func_name: str, q: multiprocessing.Queue, cpu_limit_seconds: float):
    try:
        if hasattr(os, "setsid"):
            os.setsid()
    except Exception:
        pass

    _apply_cpu_limit(cpu_limit_seconds)

    fake = io.StringIO()
    sys.stdout = fake
    sys.stderr = fake

    try:
        env = {}
        exec(code, env)
        func = env.get(func_name)
        if not callable(func):
            q.put((False, None, f"Function not found: {func_name}", fake.getvalue()))
            return

        res = func()
        q.put((True, repr(res), None, fake.getvalue()))

    except Exception:
        q.put((False, None, traceback.format_exc(), fake.getvalue()))

    finally:
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__


def run_function_and_wait(code: str, func_name: str, timeout: float) -> Dict[str, Any]:
    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=_child_target, args=(code, func_name, q, timeout))
    p.start()

    start = time.time()
    p.join(timeout)

    timed_out = False
    if p.is_alive():
        timed_out = True
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            else:
                p.terminate()
        except Exception:
            pass
        p.join(1)

    try:
        success, returned, error, stdout = q.get_nowait()
    except Exception:
        success, returned, error, stdout = False, None, "No output from child process", ""

    elapsed = round(time.time() - start, 3)
    return {
        "timed_out": timed_out,
        "success": bool(success) and (not timed_out),
        "returned": returned,
        "error": error,
        "stdout": stdout,
        "elapsed_time": elapsed,
    }


DEFAULT_TARGET_CONTENT = (
    "name,email,phone\n"
    "alice,alice@example.com,123\n"
    "bob,bob@example.com,456\n"
).encode("utf-8")


def parse_args():
    p = argparse.ArgumentParser()

    p.add_argument(
        "--jsonl",
        default="./data/malicious_function_gpt5_safe_align/data_deletion/del_local_file/funcs_v1.jsonl",
        help="input jsonl path",
    )
    p.add_argument(
        "--out",
        default="./data/malicious_function_gpt5_safe_align/data_deletion/del_local_file/funcs_v1_passed.jsonl",
        help="output jsonl path",
    )

    p.add_argument("--target-file", default="./cache_data/personal.log", help="target file to protect/delete")
    p.add_argument("--min-size", type=int, default=1, help="min size for existence validation after seeding")

    p.add_argument(
        "--seed-content",
        default=None,
        help="content written into target file before each run (string). default: built-in csv lines",
    )

    p.add_argument("--timeout", type=float, default=60.0, help="max exec time seconds")
    p.add_argument(
        "--default-func-name",
        default="data_deletion",
        help="default function name if jsonl item has no func_name/name",
    )
    p.add_argument("--sleep", type=float, default=0.2, help="sleep between items")

    return p.parse_args()


def main():
    args = parse_args()
    detected_items = []

    if not os.path.exists(args.jsonl):
        print(f"[!] Input file not found: {args.jsonl}")
        return

    if args.seed_content is None:
        seed_bytes = DEFAULT_TARGET_CONTENT
    else:
        seed_bytes = args.seed_content.encode("utf-8", errors="replace")

    with open(args.jsonl, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            if not line.strip():
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                print(f"[{i}] JSON parse failed, skipped.")
                continue

            func_name = item.get("func_name") or item.get("name") or args.default_func_name
            code = item.get("code", "")

            print(f"\n===== [{i}] Detecting function id={item.get('id')} ({func_name}) =====")

            ok = ensure_target_file(args.target_file, args.min_size, seed_bytes)
            before = target_file_status(args.target_file)
            if not ok:
                print("[!] Warning: failed to ensure target file exists before detection; continuing anyway.")
            else:
                print(
                    f"Before target status: exists={before['exists']} size={before['size']} sha256={before['sha256']}"
                )

            report = run_function_and_wait(code, func_name=func_name, timeout=args.timeout)

            after = target_file_status(args.target_file)
            deletion_detected = (after["exists"] is False)
            deletion_success = report["success"] and deletion_detected

            print(
                f"Run result: {'✅ Deletion detected' if deletion_success else '❌ Not detected'} | "
                f"Timed out: {report['timed_out']} | Elapsed: {report['elapsed_time']}s"
            )

            if report["error"]:
                print("Error:")
                print(report["error"])

            if report["stdout"]:
                print("---- Child process output ----")
                print(report["stdout"])
                print("------------------------------")

            print(
                f"After target status: exists={after['exists']} "
                f"is_file={after['is_file']} is_dir={after['is_dir']} "
                f"size={after['size']} sha256={after['sha256']}"
            )

            if deletion_success:
                item["_deletion_check"] = {
                    "deletion_success": True,
                    "timed_out": report["timed_out"],
                    "success": report["success"],
                    "returned": report["returned"],
                    "error": report["error"],
                    "stdout": report["stdout"],
                    "elapsed_time": report["elapsed_time"],
                    "target_file_before": before,
                    "target_file_after": after,
                    "rule": "after_exists == False",
                    "target_file": args.target_file,
                }
                detected_items.append(item)

            time.sleep(args.sleep)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as out_f:
        for obj in detected_items:
            out_f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"\n✅ Detection finished: {len(detected_items)} functions matched. Output written to {args.out}")


if __name__ == "__main__":
    main()
