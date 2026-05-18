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

st.title("Log Normalizer → Combined CSV Export")
st.markdown(
    "Upload a ZIP or TGZ archive containing nginx, Apache, or CloudFront logs."
)

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
# Supports .log + .gz
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
# Open Log File
# Supports .log + .gz
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

def parse_apache_line(line):

    pattern = r'^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d+) \S+ "(.*?)" "(.*?)"$'

    match = re.match(pattern, line)

    if not match:
        return None

    ip, timestamp, request, status, referer, user_agent = match.groups()

    request_parts = request.split(" ")

    path = request_parts[1] if len(request_parts) > 1 else None

    return {
        "_time": timestamp,
        "request.path": path,
        "request.userAgent": user_agent,
    }

# -----------------------------------
# Parse CloudFront Logs
# -----------------------------------

def parse_cloudfront(file_path):

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
                "request.path": row.get("cs-uri-stem"),
                "request.userAgent": row.get("cs(User-Agent)"),
            })

    return rows

# -----------------------------------
# Main Processing
# -----------------------------------

if uploaded_file:

    with tempfile.TemporaryDirectory() as temp_dir:

        archive_path = os.path.join(
            temp_dir,
            uploaded_file.name
        )

        # Save uploaded archive
        with open(archive_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        # Extraction folder
        extract_dir = os.path.join(temp_dir, "extracted")

        os.makedirs(extract_dir, exist_ok=True)

        # -----------------------------------
        # Extract ZIP
        # -----------------------------------

        if uploaded_file.name.endswith(".zip"):

            with zipfile.ZipFile(
                archive_path,
                "r"
            ) as zip_ref:

                zip_ref.extractall(extract_dir)

        # -----------------------------------
        # Extract TGZ / TAR.GZ
        # -----------------------------------

        elif (
            uploaded_file.name.endswith(".tgz")
            or uploaded_file.name.endswith(".tar.gz")
            or uploaded_file.name.endswith(".gz")
        ):

            with tarfile.open(
                archive_path,
                "r:gz"
            ) as tar:

                tar.extractall(path=extract_dir)

        else:

            st.error("Unsupported archive format.")
            st.stop()

        # -----------------------------------
        # Find All Files
        # -----------------------------------

        log_files = list(
            Path(extract_dir).rglob("*")
        )

        log_files = [
            f for f in log_files
            if f.is_file()
        ]

        st.success(f"Found {len(log_files)} files")

        all_rows = []

        progress_bar = st.progress(0)

        # -----------------------------------
        # Process Each File
        # -----------------------------------

        for idx, file_path in enumerate(log_files):

            try:

                sample = read_first_line(file_path)

                log_type = detect_format(sample)

                st.write(
                    f"Parsing: {file_path.name} ({log_type})"
                )

                # -----------------------------------
                # Apache/nginx
                # -----------------------------------

                if log_type == "apache":

                    with open_log_file(file_path) as f:

                        for line in f:

                            parsed = parse_apache_line(line)

                            if parsed:
                                all_rows.append(parsed)

                # -----------------------------------
                # CloudFront
                # -----------------------------------

                elif log_type == "cloudfront":

                    rows = parse_cloudfront(file_path)

                    all_rows.extend(rows)

            except Exception as e:

                st.error(
                    f"Error parsing {file_path}: {e}"
                )

            progress_bar.progress(
                (idx + 1) / len(log_files)
            )

        # -----------------------------------
        # Output Final CSV
        # -----------------------------------

        if all_rows:

            df = pd.DataFrame(all_rows)

            # Keep ONLY required columns
            final_columns = [
                "_time",
                "request.path",
                "request.userAgent"
            ]

            export_df = df[final_columns].copy()

            # Remove empty rows
            export_df = export_df.dropna(
                subset=["_time", "request.path"]
            )

            st.success(
                f"Parsed {len(export_df)} rows"
            )

            st.subheader(
                "Combined CSV Preview"
            )

            st.dataframe(
                export_df.head(50),
                use_container_width=True
            )

            # -----------------------------------
            # Export CSV
            # -----------------------------------

            csv_data = export_df.to_csv(
                index=False
            ).encode("utf-8")

            st.download_button(
                label="Download combined_data.csv",
                data=csv_data,
                file_name="combined_data.csv",
                mime="text/csv"
            )

        else:

            st.warning(
                "No parsable log data found."
            )
