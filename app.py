import streamlit as st
import pandas as pd
import tempfile
import zipfile
import tarfile
import gzip
import os
import re
from pathlib import Path

# -----------------------------------
# Streamlit Config
# -----------------------------------

st.set_page_config(
    page_title="Log Normalizer",
    layout="wide"
)

st.title("Log Normalizer → CSV Export")
st.markdown("Upload a ZIP or TGZ archive containing log files.")

# -----------------------------------
# Upload File
# -----------------------------------

uploaded_file = st.file_uploader(
    "Upload ZIP or TGZ File",
    type=["zip", "tgz", "gz", "tar.gz"]
)

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
# Read First Line
# Handles .log and .gz
# -----------------------------------

def read_first_line(file_path):

    if str(file_path).endswith(".gz"):

        with gzip.open(
            file_path,
            "rt",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            return f.readline()

    else:

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            return f.readline()

# -----------------------------------
# Open File Stream
# -----------------------------------

def open_log_file(file_path):

    if str(file_path).endswith(".gz"):

        return gzip.open(
            file_path,
            "rt",
            encoding="utf-8",
            errors="ignore"
        )

    return open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    )

# -----------------------------------
# Parse Apache/nginx Logs
# -----------------------------------

def parse_apache_line(line, source_file):

    pattern = r'^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d+) \S+ "(.*?)" "(.*?)"$'

    match = re.match(pattern, line)

    if not match:
        return None

    ip, timestamp, request, status, referer, user_agent = match.groups()

    request_parts = request.split(" ")

    method = request_parts[0] if len(request_parts) > 0 else None
    path = request_parts[1] if len(request_parts) > 1 else None

    return {
        "_time": timestamp,
        "request.method": method,
        "request.path": path,
        "response.status": status,
        "request.userAgent": user_agent,
        "request.host": ip,
        "request.referer": referer,
        "source.file": source_file,
    }

# -----------------------------------
# Parse CloudFront Logs
# -----------------------------------

def parse_cloudfront(file_path, source_file):

    rows = []

    with open_log_file(file_path) as f:

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

        archive_path = os.path.join(temp_dir, uploaded_file.name)

        # Save uploaded archive
        with open(archive_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        # Extract location
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        # -----------------------------------
        # Extract ZIP
        # -----------------------------------

        if uploaded_file.name.endswith(".zip"):

            with zipfile.ZipFile(archive_path, "r") as zip_ref:
                zip_ref.extractall(extract_dir)

        # -----------------------------------
        # Extract TGZ / TAR.GZ
        # -----------------------------------

        elif (
            uploaded_file.name.endswith(".tgz")
            or uploaded_file.name.endswith(".tar.gz")
            or uploaded_file.name.endswith(".gz")
        ):

            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(path=extract_dir)

        else:

            st.error("Unsupported archive format.")
            st.stop()

        # -----------------------------------
        # Find Log Files
        # -----------------------------------

        log_files = list(Path(extract_dir).rglob("*"))

        log_files = [
            f for f in log_files
            if f.is_file()
        ]

        st.success(f"Found {len(log_files)} files")

        all_rows = []

        progress_bar = st.progress(0)

        # -----------------------------------
        # Process Files
        # -----------------------------------

        for idx, file_path in enumerate(log_files):

            try:

                sample = read_first_line(file_path)

                log_type = detect_format(sample)

                st.write(f"Parsing: {file_path.name} ({log_type})")

                # Apache/nginx logs
                if log_type == "apache":

                    with open_log_file(file_path) as f:

                        for line in f:

                            parsed = parse_apache_line(
                                line,
                                str(file_path)
                            )

                            if parsed:
                                all_rows.append(parsed)

                # CloudFront logs
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

            df = pd.DataFrame(all_rows)

            st.success(f"Parsed {len(df)} rows")

            st.subheader("Preview")

            st.dataframe(
                df.head(50),
                use_container_width=True
            )

            # CSV Export
            csv_data = df.to_csv(index=False).encode("utf-8")

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
                    df.groupby("response.status")
                    .size()
                    .reset_index(name="count")
                    .sort_values("count", ascending=False)
                )

                st.bar_chart(
                    status_counts.set_index("response.status")
                )

            st.subheader("Top Request Paths")

            if "request.path" in df.columns:

                top_paths = (
                    df.groupby("request.path")
                    .size()
                    .reset_index(name="count")
                    .sort_values("count", ascending=False)
                    .head(10)
                )

                st.dataframe(
                    top_paths,
                    use_container_width=True
                )

        else:

            st.warning("No parsable log data found.")
