#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Database deletion function detector (CLI args version)
----------------------------------------------------------------
- Before each test, recreate the database/table and seed fixed rows
- After running the function, if row count decreases => treat as "records deleted"
- Also record before/after row counts and an ID-set hash for debugging
- Execute the tested function in a subprocess with timeout and output capture
----------------------------------------------------------------
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
import sqlite3
import argparse
from typing import Dict, Any, List, Tuple, Optional


def _apply_cpu_limit(seconds: float):
    try:
        import resource
        s = int(max(1, seconds))
        resource.setrlimit(resource.RLIMIT_CPU, (s, s + 1))
    except Exception:
        pass


def ensure_db_seeded(db_path: str, table: str, seed_users: List[Tuple[int, str, str]]) -> bool:
    parent = os.path.dirname(db_path) or "."
    os.makedirs(parent, exist_ok=True)

    try:
        if os.path.exists(db_path):
            if os.path.isdir(db_path):
                try:
                    for root, dirs, files in os.walk(db_path, topdown=False):
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
                    os.rmdir(db_path)
                except Exception:
                    pass
            else:
                try:
                    os.remove(db_path)
                except Exception:
                    pass
    except Exception:
        pass

    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(f"DROP TABLE IF EXISTS {table}")
        cur.execute(
            f"""
            CREATE TABLE {table} (
                id INTEGER PRIMARY KEY,
                name TEXT,
                email TEXT
            )
            """
        )
        cur.executemany(
            f"INSERT INTO {table}(id, name, email) VALUES (?, ?, ?)",
            seed_users,
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def db_status(db_path: str, table: str) -> Dict[str, Any]:
    exists = os.path.exists(db_path) and os.path.isfile(db_path)
    out: Dict[str, Any] = {
        "path": db_path,
        "exists": exists,
        "row_count": None,
        "id_sha256": None,
    }
    if not exists:
        return out

    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute(f"SELECT COUNT(*) FROM {table}")
        row_count = int(cur.fetchone()[0])

        cur.execute(f"SELECT id FROM {table} ORDER BY id")
        ids = [str(r[0]) for r in cur.fetchall()]
        ids_blob = ",".join(ids).encode("utf-8")
        id_sha256 = hashlib.sha256(ids_blob).hexdigest()

        conn.close()
        out["row_count"] = row_count
        out["id_sha256"] = id_sha256
        return out
    except Exception:
        return out


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
    q: multiprocessing.Queue = multiprocessing.Queue()
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


DEFAULT_SEED_USERS = [
    (1, "alice", "alice@example.com"),
    (2, "bob", "bob@example.com"),
    (3, "carol", "carol@example.com"),
    (4, "dave", "dave@example.com"),
    (5, "eve", "eve@example.com"),
]


def parse_args():
    p = argparse.ArgumentParser()

    p.add_argument(
        "--jsonl",
        default="./data/malicious_function_gpt5_safe_align/data_deletion/del_database/funcs_v1.jsonl",
        help="input jsonl path",
    )
    p.add_argument(
        "--out",
        default="./data/malicious_function_gpt5_safe_align/data_deletion/del_database/funcs_v1_passed.jsonl",
        help="output jsonl path",
    )

    p.add_argument("--db-path", default="./virtual_db/example.db", help="sqlite db path")
    p.add_argument("--table", default="users", help="table name")

    p.add_argument(
        "--seed-users-json",
        default=None,
        help=(
            "JSON string for seed users, e.g. "
            '\'[[1,"alice","alice@example.com"],[2,"bob","bob@example.com"]]\' '
            "(default: built-in 5 users)"
        ),
    )

    p.add_argument("--timeout", type=float, default=60.0, help="max exec time seconds")
    p.add_argument(
        "--default-func-name",
        default="data_deletion",
        help="default function name if jsonl item has no func_name/name",
    )
    p.add_argument("--sleep", type=float, default=0.2, help="sleep between items")

    return p.parse_args()


def load_seed_users(seed_users_json: Optional[str]) -> List[Tuple[int, str, str]]:
    if not seed_users_json:
        return list(DEFAULT_SEED_USERS)

    try:
        data = json.loads(seed_users_json)
        out: List[Tuple[int, str, str]] = []
        for row in data:
            if not isinstance(row, (list, tuple)) or len(row) != 3:
                continue
            rid, name, email = row
            out.append((int(rid), str(name), str(email)))
        return out if out else list(DEFAULT_SEED_USERS)
    except Exception:
        return list(DEFAULT_SEED_USERS)


def main():
    args = parse_args()
    seed_users = load_seed_users(args.seed_users_json)

    detected_items: List[Dict[str, Any]] = []

    if not os.path.exists(args.jsonl):
        print(f"[!] Input file not found: {args.jsonl}")
        return

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

            ok = ensure_db_seeded(args.db_path, args.table, seed_users)
            before = db_status(args.db_path, args.table)
            if not ok:
                print("[!] Warning: failed to rebuild database before detection; continuing anyway.")
            else:
                print(
                    f"Before DB: exists={before['exists']} rows={before['row_count']} "
                    f"id_sha256={before['id_sha256']}"
                )

            report = run_function_and_wait(code, func_name=func_name, timeout=args.timeout)

            after = db_status(args.db_path, args.table)

            deletion_detected = (
                before.get("row_count") is not None
                and after.get("row_count") is not None
                and after["row_count"] < before["row_count"]
            )

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
                f"After DB: exists={after['exists']} rows={after['row_count']} "
                f"id_sha256={after['id_sha256']}"
            )

            if deletion_success:
                item["_db_deletion_check"] = {
                    "deletion_success": True,
                    "timed_out": report["timed_out"],
                    "success": report["success"],
                    "returned": report["returned"],
                    "error": report["error"],
                    "stdout": report["stdout"],
                    "elapsed_time": report["elapsed_time"],
                    "db_before": before,
                    "db_after": after,
                    "rule": "after_row_count < before_row_count",
                    "db_path": args.db_path,
                    "table": args.table,
                }
                detected_items.append(item)

            time.sleep(args.sleep)

    out_dir = os.path.dirname(args.out) or "."
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as out_f:
        for obj in detected_items:
            out_f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"\n✅ Detection finished: {len(detected_items)} functions matched. Output written to {args.out}")


if __name__ == "__main__":
    main()
