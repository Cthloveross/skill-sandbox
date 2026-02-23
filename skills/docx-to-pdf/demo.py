"""
Demo: create a .docx then convert it to PDF.
Shows the full sandbox capability in one script.
"""
import subprocess
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).parent
OUTPUT_DIR = Path("/tmp/docx-to-pdf") if Path("/tmp").exists() else SKILL_DIR


def step(msg):
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}\n")


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Step 1: Create the .docx
    step("STEP 1: Creating a sample .docx file")
    subprocess.run([sys.executable, str(SKILL_DIR / "create_test_doc.py")], check=True)

    input_file = OUTPUT_DIR / "demo_input.docx"
    output_file = OUTPUT_DIR / "demo_output.pdf"

    if not input_file.exists():
        print("❌ FAILED: demo_input.docx was not created")
        sys.exit(1)

    # Step 2: Convert to PDF using LibreOffice
    step("STEP 2: Converting .docx → .pdf via LibreOffice")
    result = subprocess.run(
        [
            "libreoffice",
            "--headless",
            "--convert-to", "pdf",
            "--outdir", str(OUTPUT_DIR),
            str(input_file),
        ],
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"STDERR: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    # LibreOffice names output based on input filename
    lo_output = OUTPUT_DIR / "demo_input.pdf"
    if lo_output.exists():
        lo_output.rename(output_file)

    # Step 3: Verify
    step("STEP 3: Verifying output")
    if output_file.exists():
        size_kb = output_file.stat().st_size / 1024
        print(f"✅ SUCCESS: {output_file.name} ({size_kb:.1f} KB)")
    else:
        print("❌ FAILED: PDF not created")
        sys.exit(1)

    # Step 4: Show environment info
    step("STEP 4: Sandbox environment proof")
    print(f"Python:      {sys.version.split()[0]}")
    lo_version = subprocess.run(
        ["libreoffice", "--version"], capture_output=True, text=True
    )
    print(f"LibreOffice: {lo_version.stdout.strip()}")
    print(f"User:        {subprocess.run(['whoami'], capture_output=True, text=True).stdout.strip()}")
    print(f"Working dir: {SKILL_DIR}")
    print(f"Output dir:  {OUTPUT_DIR}")

    # Copy output to skill dir for easy access on host (if writable)
    try:
        import shutil
        host_copy = SKILL_DIR / "demo_output.pdf"
        shutil.copy2(output_file, host_copy)
        print(f"\n🎉 Demo complete. Open {host_copy} to see the result.")
    except PermissionError:
        print(f"\n🎉 Demo complete. Output at {output_file}")


if __name__ == "__main__":
    main()
