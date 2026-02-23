---
name: docx-to-pdf
description: "Create a Word document and convert it to PDF using LibreOffice"
network: false
---

## What this skill does
Demonstrates the full sandbox capability:
1. Creates a `.docx` file using `python-docx`
2. Converts it to `.pdf` using headless LibreOffice
3. Verifies the output and prints environment info

This is a great demo skill because it exercises multiple sandbox layers
(Python packages + system packages + non-root user).

## Dependencies
- Python: `python-docx`
- System: `libreoffice` (headless)

## Run
```bash
# Full demo (create docx → convert to PDF)
make run SKILL=docx-to-pdf ENTRY=demo.py

# Just create the test .docx
make run SKILL=docx-to-pdf ENTRY=create_test_doc.py
```

## Output
- `demo_input.docx` — the generated Word document
- `demo_output.pdf` — the converted PDF
