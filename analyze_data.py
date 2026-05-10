import pandas as pd
from cve_loader import load_cve_dataset
import os
import csv
import matplotlib.pyplot as plt
import seaborn as sns

OUTPUT_DIR = "data"

# ─────────────────────────────────────────────
# 0. SETUP
# ─────────────────────────────────────────────
def setup():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    sns.set_theme(style="whitegrid")


# ─────────────────────────────────────────────
# 1. LOAD DATA
# ─────────────────────────────────────────────
def load_data():
    files = [
        "tables/datasets/cves_full_argo_cd.csv",
        "tables/datasets/cves_full_azure_devops.csv",
        "tables/datasets/cves_full_bamboo.csv",
        "tables/datasets/cves_full_github.csv",
        "tables/datasets/cves_full_gitlab.csv",
        "tables/datasets/cves_full_jenkins.csv",
        "tables/datasets/cves_full_teamcity.csv",
        "tables/datasets/cves_full_tekton.csv",
        "tables/datasets/cves_full_travis_ci.csv"
    ]

    projects = [
        "argo_cd",
        "azure_devops",
        "bamboo",
        "github",
        "gitlab",
        "jenkins",
        "teamcity",
        "tekton",
        "travis_ci"
    ]

    dfs = []

    for file, project in zip(files, projects):
        df = load_cve_dataset(file)
        df["project"] = project
        dfs.append(df)

    return pd.concat(dfs, ignore_index=True)


# ─────────────────────────────────────────────
# 2. FEATURE ENGINEERING
# ─────────────────────────────────────────────
def extract_project(configs):
    if not configs:
        return None

    for config in configs:
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                parts = cpe.get("criteria", "").split(":")
                if len(parts) > 4:
                    return parts[3]
    return None


def extract_cwes(weaknesses):
    if not weaknesses:
        return []

    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            val = d.get("value", "")
            if "CWE-" in val:
                cwes.append(val)
    return cwes


def extract_cvss_detailed(metrics):
    if not metrics:
        return pd.Series([None, None], index=["cvss_score", "cvss_version"])

    for key, version in [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0")
    ]:
        if key in metrics:
            try:
                score = metrics[key][0]["cvssData"]["baseScore"]
                return pd.Series([score, version], index=["cvss_score", "cvss_version"])
            except:
                continue

    return pd.Series([None, None], index=["cvss_score", "cvss_version"])


def feature_engineering(df):
    df["year"] = pd.to_datetime(df["published"]).dt.year
    df["project_extracted"] = df["configurations"].apply(extract_project)
    df["cwes"] = df["weaknesses"].apply(extract_cwes)

    cvss_data = df["metrics"].apply(extract_cvss_detailed)
    df = pd.concat([df, cvss_data], axis=1)

    return df


# ─────────────────────────────────────────────
# 3. ANALYSIS TABLES
# ─────────────────────────────────────────────
def create_analysis_tables(df):
    exploded = df.explode("cwes")

    pivot_cwe = pd.pivot_table(
        exploded,
        index="project",
        columns="cwes",
        values="id",
        aggfunc="count",
        fill_value=0,
        margins=True,
        margins_name="Total"
    )

    pivot_year = pd.pivot_table(
        df,
        index="year",
        columns="project",
        values="id",
        aggfunc="count",
        fill_value=0,
        margins=True,
        margins_name="Total"
    )

    cwe_counts = (
        exploded.groupby(["project", "cwes"])
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )

    return exploded, pivot_cwe, pivot_year, cwe_counts


# ─────────────────────────────────────────────
# 4. CVSS ANALYSIS
# ─────────────────────────────────────────────
def cvss_analysis(df):
    risk_by_version = df.groupby(["project", "cvss_version"])["cvss_score"].mean().unstack()
    version_counts = df.groupby("project")["cvss_version"].value_counts().unstack(fill_value=0)

    risk_by_version.to_csv(f"{OUTPUT_DIR}/cvss_risk_averages.csv")
    version_counts.to_csv(f"{OUTPUT_DIR}/cvss_version_distribution.csv")

    df[["id", "project", "cvss_score", "cvss_version"]].to_csv(
        f"{OUTPUT_DIR}/cvss_detailed_scores.csv", index=False
    )

    return risk_by_version, version_counts


# ─────────────────────────────────────────────
# 5. SAVE BASE TABLES
# ─────────────────────────────────────────────
def save_tables(df, pivot_cwe, pivot_year, cwe_counts):
    pivot_cwe.to_csv(f"{OUTPUT_DIR}/pivot_cwe.csv")
    pivot_year.to_csv(f"{OUTPUT_DIR}/pivot_year.csv")
    cwe_counts.to_csv(f"{OUTPUT_DIR}/cwe_counts.csv", index=False)
    df.to_csv(f"{OUTPUT_DIR}/cves_processed_full.csv", index=False)



# ─────────────────────────────────────────────
# 7. VISUALIZATION
# ─────────────────────────────────────────────
def generate_plots(pivot_year, cwe_counts, df):

    # Evolution
    plot_year_df = pivot_year.drop('Total', axis=0, errors='ignore') \
                             .drop('Total', axis=1, errors='ignore')

    plt.figure(figsize=(10, 6))
    plot_year_df.plot(marker='o')
    plt.savefig("tables/evolution_plot.png")
    plt.show()

    # Top CWEs
    plt.figure(figsize=(10, 6))
    sns.barplot(data=cwe_counts.head(10), x='count', y='cwes', hue='project')
    plt.savefig("tables/top_cwes_bar.png")
    plt.show()

    # CVSS
    plt.figure(figsize=(10, 6))
    sns.boxplot(
        data=df.dropna(subset=['cvss_score']),
        x='cvss_version',
        y='cvss_score',
        hue='project'
    )
    plt.ylim(0, 10)
    plt.savefig("tables/cvss_boxplot.png")
    plt.show()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    setup()

    df = load_data()
    df = feature_engineering(df)

    exploded, pivot_cwe, pivot_year, cwe_counts = create_analysis_tables(df)

    cvss_analysis(df)
    save_tables(df, pivot_cwe, pivot_year, cwe_counts)

    generate_plots(pivot_year, cwe_counts, df)


if __name__ == "__main__":
    main()