import csv
import json
import logging
import os
from time import sleep
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
KEYWORDS: list[str] = [
    # Argo CD
    "argo cd", "argocd", "argo-cd", "argoproj",
    # Azure DevOps
    "azure devops", "azure devops server", "team foundation server",
    # Bamboo / Bitbucket (Atlassian)
    "bamboo", "bitbucket", "bitbucket server", "bitbucket data center",
    # GitHub
    "github", "github actions", "github enterprise server", "actions runner",
    "actions toolkit", "codeql",
    # GitLab
    "gitlab", "gitlab-shell", "gitlab runner",
    # Jenkins
    "jenkins", "cloudbees",
    # TeamCity
    "teamcity", "jetbrains teamcity",
    # Tekton
    "tekton", "tekton pipelines",
    # Travis CI
    "travis ci", "travis-ci",
    #pipeline related words
    "pipeline", "poisoned pipeline execution", "workflow", "runner", "build agent", "ci/cd", "continuous integration",
    "build server", "merge request", "pull request", "repository"
]
REQUEST_DELAY = 0.6
RESULTS_PER_PAGE = 2000
OUTPUT_FILE      = "data/new_datasets/dataset_cve.csv"
CPES: dict[str, list[str]] = {
    "argo_cd": [
        "cpe:2.3:a:argoproj:argo_cd:",
        "cpe:2.3:a:linuxfoundation:argo-cd:",
    ],
    "azure_devops": [
        "cpe:2.3:o:microsoft:azure_devops_server:",
    ],
    "bamboo": [
        "cpe:2.3:a:atlassian:bamboo:",
    ],
    "bitbucket": [
        "cpe:2.3:a:atlassian:bitbucket:",
        "cpe:2.3:a:atlassian:bitbucket_data_center:",
        "cpe:2.3:a:atlassian:bitbucket_server:",
    ],
    "github": [
        "cpe:2.3:a:github:actions:",
        "cpe:2.3:a:github:actions_toolkit:",
        "cpe:2.3:a:github:codeql_action:",
        "cpe:2.3:a:github:enterprise_server:",
        "cpe:2.3:a:github:runner:",
    ],
    "gitlab": [
        "cpe:2.3:a:gitlab:gitlab:",
    ],
    "jenkins": [
        "cpe:2.3:a:cloudbees:jenkins:",
        "cpe:2.3:a:jenkins:jenkins:",
    ],
    "teamcity": [
        "cpe:2.3:a:jetbrains:teamcity:",
    ],
    "tekton": [
        "cpe:2.3:a:linuxfoundation:tekton_pipelines:",
    ],
    "travis_ci": [
        "cpe:2.3:a:travis-ci:travis_ci:",
    ],
}
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

    os.makedirs(os.path.dirname(path), exist_ok=True)
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    logging.info("Wrote %d rows to '%s'.", len(rows), path)


# ── API ────────────────────────────────────────────────────────────────────────
def fetch_from_api() -> list[dict[str, Any]]:
    """Fetches vulnerabilities for each keyword, one at a time, deduplicating by CVE id."""
    if not API_URL or not API_KEY:
        raise EnvironmentError("API_URL and API_KEY must be set in the .env file.")

    headers = {"apiKey": API_KEY}
    all_vulns: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for keyword in KEYWORDS:
        logging.info("Fetching vulnerabilities for keyword: %s", keyword)
        start_index = 0

        while True:
            params = {
                "keywordSearch":  keyword,
                "resultsPerPage": RESULTS_PER_PAGE,
                "startIndex":     start_index,
            }
            try:
                response = requests.get(API_URL, params=params, headers=headers, timeout=30)
                response.raise_for_status()
            except requests.HTTPError:
                nvd_msg = response.headers.get("message", "no message header")
                logging.error("HTTP %s — NVD message: %s (keyword: %s)",
                              response.status_code, nvd_msg, keyword)
                raise

            data  = response.json()
            vulns = data.get("vulnerabilities", [])
            total = data.get("totalResults", 0)

            new_count = 0
            for v in vulns:
                cve_id = v["cve"].get("id")
                if cve_id not in seen_ids:
                    seen_ids.add(cve_id)
                    all_vulns.append(v)
                    new_count += 1

            logging.info("[%s] página: %d resultados (%d novos) | total keyword: %d | acumulado: %d",
                         keyword, len(vulns), new_count, total, len(all_vulns))

            sleep(REQUEST_DELAY)

            if start_index + len(vulns) >= total:
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

def matched_project(vuln: dict[str, Any]) -> str | None:
    """Return the first project whose CPEs match this CVE, or None."""
    for project, cpes in CPES.items():
        if any(verify_vulnerability_cpe(vuln, cpe) for cpe in cpes):
            return project
    return None

# ── Entry point ────────────────────────────────────────────────────────────────
def main() -> None:
    vulnerabilities = fetch_from_api()
    rows = []
    for v in vulnerabilities:
        project = matched_project(v)
        if project:
            row = extract_data(v)
            row["project"] = project
            rows.append(row)
    write_csv(rows)

if __name__ == "__main__":
    main()