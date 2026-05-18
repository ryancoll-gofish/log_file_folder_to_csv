import streamlit as st
import pandas as pd
import tempfile
import zipfile
import os
import re
from pathlib import Path
from apachelogs import LogParser

# -----------------------------------
# Streamlit Config
# -----------------------------------

st.set_page_config(
    page_title="Log Normalizer",
    layout="wide"
)

st.title("Log Normalizer → CSV Export")
st.markdown("Upload a ZIP file containing log files.")

# -----------------------------------
# Upload File
# -----------------------------------

uploaded_file = st.file_uploader(
    "Upload ZIP File",
    type=["zip"]
)

# -----------------------------------
# Apache/nginx Parser Setup
# -----------------------------------

APACHE_FORMAT = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'

parser = LogParser(APACHE_FORMAT)

# -----------------------------------
# Detect Log Format
# -----------------------------------

def detect_format(sample):

    if "\t" in sample and "#Version:" in sample:
        return "cloudfront"

    if re.search(r'"(GET|POST|PUT|DELETE)', sample):
        return "apache"

    return "unknown"

# -----------------------------------
# Parse Apache/nginx Logs
# -----------------------------------

def parse_apache_line(line, source_file):

    try:
        entry = parser.parse(line)

        request_parts = entry.request_line.split(" ")

        method = request_parts[0] if len(request_parts) > 0 else None
        path = request_parts[1] if len(request_parts) > 1 else None

        return {
            "_time": str(entry.request_time),
            "request.method": method,
            "request.path": path,
            "response.status": entry.final_status,
            "request.userAgent": entry.headers_in.get("User-Agent"),
            "request.host": entry.headers_in.get("Host"),
            "request.referer": entry.headers_in.get("Referer"),
            "source.file": source_file,
        }

    except Exception:
        return None

# -----------------------------------
# Parse CloudFront Logs
# -----------------------------------

def parse_cloudfront(file_path, source_file):

    rows = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:

        headers = []

        for line in f:

            if line.startswith("#Fields:"):
                headers = line.strip().replace("#Fields: ", "").split("\t")
                continue

            if line.startswith("#"):
                continue

            if not headers:
                continue

            values = line.strip().split("\t")

            if len(values) != len(headers):
                continue

            row = dict(zip(headers, values))

            rows.append({
                "_time": f'{row.get("date", "")}T{row.get("time", "")}',
                "request.method": row.get("cs-method"),
                "request.path": row.get("cs-uri-stem"),
                "response.status": row.get("sc-status"),
                "request.userAgent": row.get("cs(User-Agent)"),
                "request.host": row.get("cs-host"),
                "request.referer": row.get("cs(Referer)"),
                "source.file": source_file,
            })

    return rows

# -----------------------------------
# Main Upload Processing
# -----------------------------------

if uploaded_file:

    with tempfile.TemporaryDirectory() as temp_dir:

        # Save ZIP
        zip_path = os.path.join(temp_dir, "logs.zip")

        with open(zip_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        # Extract ZIP
        extract_dir = os.path.join(temp_dir, "extracted")

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extract_dir)

        # Find Log Files
        log_files = list(Path(extract_dir).rglob("*.log"))

        st.success(f"Found {len(log_files)} log files")

        all_rows = []

        progress_bar = st.progress(0)

        # Process Each File
        for idx, file_path in enumerate(log_files):

            try:

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    sample = f.readline()

                log_type = detect_format(sample)

                st.write(f"Parsing: {file_path.name} ({log_type})")

                # Apache/nginx
                if log_type == "apache":

                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:

                        for line in f:

                            parsed = parse_apache_line(
                                line,
                                str(file_path)
                            )

                            if parsed:
                                all_rows.append(parsed)

                # CloudFront
                elif log_type == "cloudfront":

                    rows = parse_cloudfront(
                        file_path,
                        str(file_path)
                    )

                    all_rows.extend(rows)

            except Exception as e:

                st.error(f"Error parsing {file_path}: {e}")

            progress_bar.progress((idx + 1) / len(log_files))

        # -----------------------------------
        # Output Results
        # -----------------------------------

        if all_rows:

            df = pl.DataFrame(all_rows)

            st.success(f"Parsed {len(df)} rows")

            st.subheader("Preview")

            st.dataframe(
                df.head(50).to_pandas(),
                use_container_width=True
            )

            # CSV Export
            csv_data = df.write_csv()

            st.download_button(
                label="Download Normalized CSV",
                data=csv_data,
                file_name="normalized_logs.csv",
                mime="text/csv"
            )

            # -----------------------------------
            # Analytics
            # -----------------------------------

            st.subheader("Status Code Distribution")

            if "response.status" in df.columns:

                status_counts = (
                    df.group_by("response.status")
                    .count()
                    .sort("count", descending=True)
                    .to_pandas()
                )

                st.bar_chart(
                    status_counts.set_index("response.status")
                )

            st.subheader("Top Request Paths")

            if "request.path" in df.columns:

                top_paths = (
                    df.group_by("request.path")
                    .count()
                    .sort("count", descending=True)
                    .head(10)
                    .to_pandas()
                )

                st.dataframe(
                    top_paths,
                    use_container_width=True
                )

        else:

            st.warning("No parsable log data found.")
