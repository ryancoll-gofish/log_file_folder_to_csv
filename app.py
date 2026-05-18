import streamlit as st

        extract_dir = os.path.join(temp_dir, "extracted")

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extract_dir)

        all_rows = []

        log_files = list(Path(extract_dir).rglob("*.log"))

        st.write(f"Found {len(log_files)} log files")

        progress_bar = st.progress(0)

        for idx, file_path in enumerate(log_files):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    sample = f.readline()

                log_type = detect_format(sample)

                st.write(f"Parsing: {file_path.name} ({log_type})")

                if log_type == "apache":
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            parsed = parse_apache_line(line, str(file_path))

                            if parsed:
                                all_rows.append(parsed)

                elif log_type == "cloudfront":
                    rows = parse_cloudfront(file_path, str(file_path))
                    all_rows.extend(rows)

            except Exception as e:
                st.error(f"Error parsing {file_path}: {e}")

            progress_bar.progress((idx + 1) / len(log_files))

        if all_rows:
            df = pl.DataFrame(all_rows)

            st.success(f"Parsed {len(df)} rows")

            st.dataframe(df.head(50).to_pandas())

            csv_data = df.write_csv()

            st.download_button(
                label="Download Normalized CSV",
                data=csv_data,
                file_name="normalized_logs.csv",
                mime="text/csv"
            )

            st.subheader("Quick Insights")

            if "response.status" in df.columns:
                status_counts = (
                    df.group_by("response.status")
                    .count()
                    .sort("count", descending=True)
                    .to_pandas()
                )

                st.bar_chart(status_counts.set_index("response.status"))

            if "request.path" in df.columns:
                top_paths = (
                    df.group_by("request.path")
                    .count()
                    .sort("count", descending=True)
                    .head(10)
                    .to_pandas()
                )

                st.subheader("Top Paths")
                st.dataframe(top_paths)

        else:
            st.warning("No parsable log data found.")
