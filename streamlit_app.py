import io
import os
import re
import zipfile
from datetime import datetime

import pandas as pd
import streamlit as st
from fpdf import FPDF


st.set_page_config(page_title="Faultless AI Audit", page_icon=":mag:", layout="wide")


def decode_bytes(content: bytes) -> str:
    """Decode bytes safely into text."""
    for encoding in ("utf-8", "latin-1", "cp1252"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    return ""


def scan_security(text: str) -> list[dict]:
    """Scan for possible hardcoded credentials and API keys."""
    findings = []
    patterns = [
        ("Hardcoded password", r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
        ("Hardcoded API key", r"(?i)\b(api[_-]?key|token|secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{8,}['\"]"),
        ("AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b"),
    ]

    lines = text.splitlines()
    for line_no, line in enumerate(lines, start=1):
        for issue_type, pattern in patterns:
            if re.search(pattern, line):
                findings.append(
                    {
                        "category": "Security",
                        "issue": issue_type,
                        "line": line_no,
                        "snippet": line.strip()[:200],
                    }
                )
    return findings


def scan_logic(text: str) -> list[dict]:
    """Scan for simple division-by-zero issues."""
    findings = []
    lines = text.splitlines()

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if re.search(r"/\s*0(\D|$)", stripped):
            findings.append(
                {
                    "category": "Logic",
                    "issue": "Possible division by zero",
                    "line": line_no,
                    "snippet": stripped[:200],
                }
            )
        elif re.search(r"//\s*0(\D|$)", stripped):
            findings.append(
                {
                    "category": "Logic",
                    "issue": "Possible floor division by zero",
                    "line": line_no,
                    "snippet": stripped[:200],
                }
            )
    return findings


def generate_pdf_report(df: pd.DataFrame, total_files: int) -> bytes:
    """Generate a PDF report for findings."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Faultless AI Audit Report", ln=True)

    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(0, 8, f"Files analyzed: {total_files}", ln=True)
    pdf.cell(0, 8, f"Total findings: {len(df)}", ln=True)
    pdf.ln(3)

    if df.empty:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "No issues found. Great job!", ln=True)
    else:
        for idx, row in df.iterrows():
            pdf.set_font("Arial", "B", 11)
            pdf.multi_cell(0, 7, f"{idx + 1}. [{row['category']}] {row['issue']}")
            pdf.set_font("Arial", "", 10)
            pdf.multi_cell(0, 6, f"File: {row['file']}  |  Line: {row['line']}")
            pdf.multi_cell(0, 6, f"Code: {str(row['snippet'])[:400]}")
            pdf.ln(1)

    pdf_output = pdf.output(dest="S")
    if isinstance(pdf_output, str):
        return pdf_output.encode("latin-1", errors="ignore")
    return bytes(pdf_output)


def extract_uploads(uploaded_files) -> tuple[list[tuple[str, str]], int]:
    """Return list of (filename, text) from direct files and ZIP archives."""
    extracted = []
    analyzed_files = 0
    allowed_ext = (
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".cs",
        ".cpp",
        ".c",
        ".h",
        ".json",
        ".yaml",
        ".yml",
        ".env",
        ".txt",
    )

    for uploaded in uploaded_files:
        filename = uploaded.name
        ext = os.path.splitext(filename)[1].lower()
        data = uploaded.read()

        if ext == ".zip":
            try:
                with zipfile.ZipFile(io.BytesIO(data), "r") as zip_ref:
                    for member in zip_ref.infolist():
                        if member.is_dir():
                            continue
                        member_ext = os.path.splitext(member.filename)[1].lower()
                        if member_ext and member_ext not in allowed_ext:
                            continue
                        try:
                            content = zip_ref.read(member)
                            text = decode_bytes(content)
                            if text.strip():
                                extracted.append((member.filename, text))
                                analyzed_files += 1
                        except Exception:
                            continue
            except zipfile.BadZipFile:
                st.warning(f"Invalid ZIP file skipped: {filename}")
        else:
            if ext and ext not in allowed_ext:
                continue
            text = decode_bytes(data)
            if text.strip():
                extracted.append((filename, text))
                analyzed_files += 1

    return extracted, analyzed_files


def main() -> None:
    st.title("Faultless AI Audit")
    st.caption("Professional static code audit for security and logic issues.")

    with st.container(border=True):
        st.subheader("Upload Source Files or ZIP")
        uploaded_files = st.file_uploader(
            "Choose files (.py, .js, etc.) or ZIP archives",
            type=[
                "py",
                "js",
                "ts",
                "jsx",
                "tsx",
                "java",
                "go",
                "rb",
                "php",
                "cs",
                "cpp",
                "c",
                "h",
                "json",
                "yaml",
                "yml",
                "env",
                "txt",
                "zip",
            ],
            accept_multiple_files=True,
            help="You can upload one or multiple files, including ZIP archives.",
        )

    run_scan = st.button("Run Faultless Audit", type="primary", use_container_width=True)

    if run_scan:
        if not uploaded_files:
            st.error("Please upload at least one file or ZIP archive.")
            return

        with st.spinner("Scanning files..."):
            extracted_files, total_files = extract_uploads(uploaded_files)

            all_findings = []
            for fname, text in extracted_files:
                security_findings = scan_security(text)
                logic_findings = scan_logic(text)

                for finding in security_findings + logic_findings:
                    finding["file"] = fname
                    all_findings.append(finding)

            findings_df = pd.DataFrame(all_findings)
            if not findings_df.empty:
                findings_df = findings_df[
                    ["file", "category", "issue", "line", "snippet"]
                ].sort_values(by=["category", "file", "line"], ascending=[True, True, True])
            else:
                findings_df = pd.DataFrame(columns=["file", "category", "issue", "line", "snippet"])

        st.success(f"Audit complete. Files analyzed: {total_files}")

        col1, col2, col3 = st.columns(3)
        col1.metric("Files Analyzed", total_files)
        col2.metric("Total Findings", len(findings_df))
        col3.metric(
            "Security Findings",
            int((findings_df["category"] == "Security").sum()) if not findings_df.empty else 0,
        )

        st.subheader("Audit Findings")
        if findings_df.empty:
            st.info("No security or logic issues found.")
        else:
            st.dataframe(findings_df, use_container_width=True, hide_index=True)

        csv_bytes = findings_df.to_csv(index=False).encode("utf-8")
        pdf_bytes = generate_pdf_report(findings_df, total_files)

        st.subheader("Export Reports")
        c1, c2 = st.columns(2)
        with c1:
            st.download_button(
                label="Download CSV Report",
                data=csv_bytes,
                file_name="faultless_ai_audit_report.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with c2:
            st.download_button(
                label="Download PDF Report",
                data=pdf_bytes,
                file_name="faultless_ai_audit_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )


if __name__ == "__main__":
    main()
