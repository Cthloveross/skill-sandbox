"""
Demo: create a .docx then convert it to PDF.
Shows the full sandbox capability in one script.
"""
import subprocess
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).parent


def step(msg):
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}\n")


def main():
    # Step 1: Create the .docx
    step("STEP 1: Creating a sample .docx file")
    exec(open(SKILL_DIR / "create_test_doc.py").read())

    input_file = SKILL_DIR / "demo_input.docx"
    output_file = SKILL_DIR / "demo_output.pdf"

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
            "--outdir", str(SKILL_DIR),
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
    lo_output = SKILL_DIR / "demo_input.pdf"
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
    print(f"\n🎉 Demo complete. Open {output_file.name} to see the result.")


if __name__ == "__main__":
    main()
