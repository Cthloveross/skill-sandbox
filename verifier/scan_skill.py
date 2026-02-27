#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_skill.py – Unified security scanner for skill scripts.

Pipeline:
  1. Extract all top-level functions from a skill's .py files  (extract.py)
  2. Set up isolated test fixtures (temp DB, temp file, temp workspace)
  3. Run every function through each applicable verifier
  4. Aggregate results → print a clear pass / FAIL report

Usage:
  python -m verifier.scan_skill --skill docx-to-pdf
  python -m verifier.scan_skill --all
  python -m verifier.scan_skill --skill docx-to-pdf --out results.jsonl
"""

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from typing import Dict, List, Any

# ── import peer modules ────────────────────────────────────────
from verifier.extract import extract_from_skill

# ── import verifier engines (the ones feasible without GPU) ────
from verifier.test_func_db import (
    run_function_with_timeout as run_db_insert,
    get_table_row_count,
)
from verifier.test_func_del_db import (
    run_function_and_wait as run_del_db,
    ensure_db_seeded,
    db_status,
    DEFAULT_SEED_USERS,
)
from verifier.test_func_del_file import (
    run_function_and_wait as run_del_file,
    ensure_target_file,
    target_file_status,
)
from verifier.test_func_dos import (
    run_with_runtime_detection as run_dos,
)
from verifier.test_func_rce import (
    run_function_and_wait as run_rce,
    cleanup_target_files,
    list_target_files,
)
from verifier.test_func_credential_abuse import (
    run_detection_on_code as run_credential,
)

# ── constants ──────────────────────────────────────────────────
SKILLS_DIR = os.path.join(os.path.dirname(__file__), "..", "skills")
DEFAULT_TIMEOUT = 10.0
DOS_THRESHOLD = 5.0

# Categories we check (GPU is skipped – no guarantee of hardware)
CHECK_NAMES = [
    "db_insert",
    "db_delete",
    "file_delete",
    "credential_abuse",
    "dos",
    "remote_code_exec",
]


# ── fixture helpers ────────────────────────────────────────────
def _make_temp_db(table: str = "users") -> str:
    """Create a seeded SQLite DB in a temp dir; return its path."""
    tmp = tempfile.mkdtemp(prefix="vfy_db_")
    db_path = os.path.join(tmp, "example.db")
    ensure_db_seeded(db_path, table, list(DEFAULT_SEED_USERS))
    return db_path


def _make_temp_target_file() -> str:
    """Create a small target file; return its path."""
    tmp = tempfile.mkdtemp(prefix="vfy_file_")
    path = os.path.join(tmp, "personal.log")
    content = b"name,email,phone\nalice,alice@example.com,123\nbob,bob@example.com,456\n"
    ensure_target_file(path, 1, content)
    return path


def _make_rce_dir() -> str:
    """Create a temp dir for remote-code-exec download artifacts."""
    tmp = tempfile.mkdtemp(prefix="vfy_rce_")
    return tmp


# ── per-check runners ─────────────────────────────────────────
def check_db_insert(code: str, func_name: str, db_path: str, timeout: float) -> Dict[str, Any]:
    """Does the function insert rows into the DB?"""
    table = "users"
    # Re-seed so every check starts clean
    ensure_db_seeded(db_path, table, list(DEFAULT_SEED_USERS))
    try:
        before = get_table_row_count(db_path, table)
    except Exception:
        return {"detected": False, "error": "could not read DB before"}

    _result, err, _out = run_db_insert(code, func_name, timeout)

    try:
        after = get_table_row_count(db_path, table)
    except Exception:
        return {"detected": False, "error": "could not read DB after"}

    return {"detected": after > before, "before": before, "after": after, "error": err}


def check_db_delete(code: str, func_name: str, db_path: str, timeout: float) -> Dict[str, Any]:
    """Does the function delete rows from the DB?"""
    table = "users"
    ensure_db_seeded(db_path, table, list(DEFAULT_SEED_USERS))
    before = db_status(db_path, table)

    report = run_del_db(code, func_name, timeout)

    after = db_status(db_path, table)
    detected = (
        before.get("row_count") is not None
        and after.get("row_count") is not None
        and after["row_count"] < before["row_count"]
    )
    return {"detected": detected, "before_rows": before.get("row_count"), "after_rows": after.get("row_count"), "error": report.get("error")}


def check_file_delete(code: str, func_name: str, target_path: str, timeout: float) -> Dict[str, Any]:
    """Does the function delete the target file?"""
    content = b"name,email,phone\nalice,alice@example.com,123\nbob,bob@example.com,456\n"
    ensure_target_file(target_path, 1, content)
    before = target_file_status(target_path)

    report = run_del_file(code, func_name, timeout)

    after = target_file_status(target_path)
    detected = before["exists"] and not after["exists"]
    return {"detected": detected, "error": report.get("error")}


def check_credential_abuse(code: str, func_name: str, timeout: float) -> Dict[str, Any]:
    """Does the function try to read .env / credential files?"""
    report = run_credential(
        code=code,
        func_name=func_name,
        max_exec_time=timeout,
        cleanup=True,
        env_filename=".env",
        env_content="DUMMY_KEY=REDACTED\nOTHER=VALUE\n",
        env_marker="ENV_ACCESS:",
        sentinel_name=".env_access_detected",
    )
    return {"detected": report.get("env_accessed", False), "evidence": report.get("evidence", []), "error": report.get("stderr")}


def check_dos(code: str, func_name: str, threshold: float, hard_limit: float) -> Dict[str, Any]:
    """Does the function run suspiciously long (possible DoS)?"""
    report = run_dos(
        code=code,
        func_name=func_name,
        runtime_threshold=threshold,
        max_exec_time=hard_limit,
    )
    return {"detected": report.get("dos_detected", False), "elapsed": report.get("elapsed_time"), "error": report.get("error")}


def check_rce(code: str, func_name: str, bin_dir: str, timeout: float) -> Dict[str, Any]:
    """Does the function download files (remote code execution)?"""
    cleanup_target_files(bin_dir, ".bin")
    report = run_rce(code, func_name, timeout)
    detected_files = list_target_files(bin_dir, ".bin", 1)
    return {"detected": len(detected_files) > 0, "files": detected_files, "error": report.get("error")}


# ── main scan logic ────────────────────────────────────────────
def scan_one_skill(skill_dir: str, timeout: float = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    """Scan every function in a skill against all checks. Return findings."""
    skill_name = os.path.basename(os.path.normpath(skill_dir))
    records = extract_from_skill(skill_dir, skill_name)

    if not records:
        print(f"  ℹ️  No Python functions found in {skill_name}")
        return []

    # Set up shared fixtures
    db_path = _make_temp_db()
    target_file = _make_temp_target_file()
    rce_dir = _make_rce_dir()

    findings: List[Dict[str, Any]] = []

    for rec in records:
        func_id = rec["id"]
        code = rec["code"]
        func_name = rec["func_name"]

        print(f"  🔍 Checking {func_id} …")

        func_findings: Dict[str, Any] = {
            "id": func_id,
            "skill": skill_name,
            "file": rec["file"],
            "func_name": func_name,
            "checks": {},
        }

        # 1. DB insert
        r = check_db_insert(code, func_name, db_path, timeout)
        func_findings["checks"]["db_insert"] = r
        if r["detected"]:
            print(f"    ⚠️  db_insert: rows {r['before']} → {r['after']}")

        # 2. DB delete
        r = check_db_delete(code, func_name, db_path, timeout)
        func_findings["checks"]["db_delete"] = r
        if r["detected"]:
            print(f"    ⚠️  db_delete: rows {r['before_rows']} → {r['after_rows']}")

        # 3. File delete
        r = check_file_delete(code, func_name, target_file, timeout)
        func_findings["checks"]["file_delete"] = r
        if r["detected"]:
            print(f"    ⚠️  file_delete: target file removed")

        # 4. Credential abuse
        r = check_credential_abuse(code, func_name, timeout)
        func_findings["checks"]["credential_abuse"] = r
        if r["detected"]:
            print(f"    ⚠️  credential_abuse: .env accessed")

        # 5. DoS
        r = check_dos(code, func_name, DOS_THRESHOLD, timeout * 2)
        func_findings["checks"]["dos"] = r
        if r["detected"]:
            print(f"    ⚠️  dos: ran for {r['elapsed']}s (threshold {DOS_THRESHOLD}s)")

        # 6. Remote code exec
        r = check_rce(code, func_name, rce_dir, timeout)
        func_findings["checks"]["remote_code_exec"] = r
        if r["detected"]:
            print(f"    ⚠️  rce: downloaded files detected")

        # Count how many checks flagged
        flagged = [k for k, v in func_findings["checks"].items() if v.get("detected")]
        func_findings["flagged_checks"] = flagged
        func_findings["is_clean"] = len(flagged) == 0

        if func_findings["is_clean"]:
            print(f"    ✅ clean")

        findings.append(func_findings)

    # Cleanup fixtures
    for path in [os.path.dirname(db_path), os.path.dirname(target_file), rce_dir]:
        try:
            shutil.rmtree(path)
        except Exception:
            pass

    return findings


# ── report ─────────────────────────────────────────────────────
def print_summary(all_findings: Dict[str, List[Dict]]):
    """Print a final summary table."""
    print("\n" + "=" * 60)
    print("  SECURITY SCAN SUMMARY")
    print("=" * 60)

    total_funcs = 0
    total_flagged = 0

    for skill_name, findings in sorted(all_findings.items()):
        clean = sum(1 for f in findings if f["is_clean"])
        flagged = len(findings) - clean
        total_funcs += len(findings)
        total_flagged += flagged

        if findings:
            status = "✅ PASS" if flagged == 0 else f"⚠️  {flagged} FLAGGED"
            print(f"  {skill_name:<30s}  {len(findings):>3d} funcs  {status}")
        else:
            print(f"  {skill_name:<30s}  (no Python functions)")

    print("-" * 60)
    if total_flagged == 0:
        print(f"  ✅ ALL CLEAR — {total_funcs} functions checked, 0 flagged")
    else:
        print(f"  ⚠️  {total_flagged}/{total_funcs} functions flagged")
    print("=" * 60)

    return total_flagged == 0


# ── CLI ────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="Scan skill scripts for malicious behavior"
    )
    p.add_argument("--skill", help="Name of a single skill to scan (e.g. docx-to-pdf)")
    p.add_argument("--all", action="store_true", help="Scan all skills")
    p.add_argument("--skills-dir", default=SKILLS_DIR, help="Path to skills/ directory")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout per function per check (seconds)")
    p.add_argument("--out", default=None, help="Write detailed JSON results to this file")
    return p.parse_args()


def main():
    args = parse_args()

    if not args.skill and not args.all:
        print("[!] Specify --skill <name> or --all")
        sys.exit(1)

    skills_dir = os.path.abspath(args.skills_dir)

    # Build list of skills to scan
    if args.all:
        skill_names = sorted([
            d for d in os.listdir(skills_dir)
            if os.path.isdir(os.path.join(skills_dir, d)) and not d.startswith("_")
        ])
    else:
        skill_names = [args.skill]

    all_findings: Dict[str, List[Dict]] = {}

    for name in skill_names:
        skill_path = os.path.join(skills_dir, name)
        if not os.path.isdir(skill_path):
            print(f"[!] Skill not found: {skill_path}")
            continue

        print(f"\n{'━' * 50}")
        print(f"  Scanning skill: {name}")
        print(f"{'━' * 50}")

        findings = scan_one_skill(skill_path, timeout=args.timeout)
        all_findings[name] = findings

    # Summary
    is_clean = print_summary(all_findings)

    # Write detailed output
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(all_findings, f, indent=2, ensure_ascii=False, default=str)
        print(f"\nDetailed results → {args.out}")

    sys.exit(0 if is_clean else 1)


if __name__ == "__main__":
    main()
