import csv
import json
import logging
import os
import pandas as pd
from typing import Any
import requests
import glob
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ── Constants ──────────────────────────────────────────────────────────────────
API_URL          = os.getenv("API_URL", "")
API_KEY          = os.getenv("API_KEY", "")
KEYWORD_SEARCH   = "bamboo"
RESULTS_PER_PAGE = 2000
OUTPUT_FILE      = "tables/datasets/cves_full_bamboo.csv"
CPE              = "cpe:2.3:a:atlassian:bamboo:"
LIST_FIELDS: list[str] = ["descriptions", "weaknesses", "configurations", "references", "cveTags"]
DICT_FIELDS: list[str] = ["metrics"]


def extract_data(vuln: dict[str, Any]) -> dict[str, Any]:
    """Flatten one raw vulnerability (JSON) entry into a CSV-friendly dict."""
    cve = vuln["cve"]

    row: dict[str, Any] = {
        "id":               cve.get("id"),
        "sourceIdentifier": cve.get("sourceIdentifier"),
        "published":        cve.get("published"),
        "lastModified":     cve.get("lastModified"),
        "vulnStatus":       cve.get("vulnStatus"),
    }

    for field in LIST_FIELDS:
        row[field] = json.dumps(cve.get(field, []), ensure_ascii=False)

    for field in DICT_FIELDS:
        row[field] = json.dumps(cve.get(field, {}), ensure_ascii=False)

    return row


def write_csv(rows: list[dict[str, Any]], path: str = OUTPUT_FILE) -> None:
    """Write extracted rows to a CSV file."""
    if not rows:
        logging.warning("No rows to write — skipping CSV creation.")
        return

    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    logging.info("Wrote %d rows to '%s'.", len(rows), path)


# ── API ────────────────────────────────────────────────────────────────────────
def fetch_from_api() -> list[dict[str, Any]]:
    """Calls the API to retrive all vulnerabilities from a specific KEYWORD_SEARCH"""
    if not API_URL or not API_KEY:
        raise EnvironmentError("API_URL and API_KEY must be set in the .env file.")

    headers = {"apiKey": API_KEY}
    all_vulns: list[dict[str, Any]] = []
    start_index = 0

    while True:
        params = {
            "keywordSearch":  KEYWORD_SEARCH,
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex":     start_index,
        }
        try:
            response = requests.get(API_URL, params=params, headers=headers, timeout=30) # Will get the responses in the API
            response.raise_for_status()
        except requests.HTTPError as exc:
            nvd_msg = response.headers.get("message", "no message header")
            logging.error("HTTP %s — NVD message: %s", response.status_code, nvd_msg)
            raise

        data  = response.json()
        vulns = data.get("vulnerabilities", [])
        with open("file.json", "w") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        total = data.get("totalResults", 0)

        all_vulns.extend(vulns)
        logging.info("Fetched %d / %d vulnerabilities.", len(all_vulns), total)

        if len(all_vulns) >= total:
            break

        start_index += RESULTS_PER_PAGE

    return all_vulns

def verify_vulnerability_cpe(vuln, target_cpe):
    configs = vuln["cve"].get("configurations", [])

    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):

                if not match.get("vulnerable", False):
                    continue

                cpe = match.get("criteria", "")
                
                if cpe.startswith(target_cpe):
                    return True

    return False

def merge_csvs(input_folder: str, output_file: str) -> None:
    """
    Junta todos os CSVs de uma pasta num único ficheiro CSV.
    """

    csv_files = glob.glob(os.path.join(input_folder, "*.csv"))

    if not csv_files:
        print("Nenhum CSV encontrado na pasta.")
        return

    dfs = []

    for file in csv_files:
        try:
            df = pd.read_csv(file)
            dfs.append(df)
            print(f"Lido: {file} ({len(df)} linhas)")
        except Exception as e:
            print(f"Erro ao ler {file}: {e}")

    if not dfs:
        print("Nenhum CSV válido para juntar.")
        return

    merged_df = pd.concat(dfs, ignore_index=True)

    if "id" in merged_df.columns:
        merged_df = merged_df.drop_duplicates(subset=["id"])

    merged_df.to_csv(output_file, index=False, encoding="utf-8")

    print(f"\nFicheiro final criado: {output_file}")
    print(f"Total de linhas: {len(merged_df)}")

# ── Entry point ────────────────────────────────────────────────────────────────
def main() -> None:
    # # We fetch all vulnerabilities with a specific keyword
    # vulnerabilities = fetch_from_api()
    # # The vulnerabilities information is transformed from json to csv.
    # rows = []
    # for v in vulnerabilities:
    #     if (verify_vulnerability_cpe(v, CPE)):
    #         rows.append(extract_data(v))
    # write_csv(rows)

    merge_csvs("tables/datasets/", "tables/datasets/cves_merged.csv")


if __name__ == "__main__":
    main()