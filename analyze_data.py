import pandas as pd
from cve_loader import load_cve_dataset
import os

# ─────────────────────────────────────────────
# 0. CREATE OUTPUT DIR
# ─────────────────────────────────────────────
os.makedirs("tables", exist_ok=True)

# ─────────────────────────────────────────────
# 1. LOAD DATA
# ─────────────────────────────────────────────
df_jenkins = load_cve_dataset("cves_full_jenkins.csv")
df_gitlab = load_cve_dataset("cves_full_gitlab.csv")


# ─────────────────────────────────────────────
# 2. ADD PROJECT LABEL
# ─────────────────────────────────────────────
df_jenkins["project"] = "jenkins"
df_gitlab["project"] = "gitlab"


# ─────────────────────────────────────────────
# 3. MERGE DATASETS
# ─────────────────────────────────────────────
df = pd.concat([df_jenkins, df_gitlab], ignore_index=True)


# ─────────────────────────────────────────────
# 4. FEATURE ENGINEERING
# ─────────────────────────────────────────────

# Year
df["year"] = pd.to_datetime(df["published"]).dt.year


# Project (optional re-extract if needed)
def extract_project(configs):
    if not configs:
        return None

    for config in configs:
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                criteria = cpe.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) > 4:
                    return parts[3]
    return None


df["project_extracted"] = df["configurations"].apply(extract_project)


# CWE extraction
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


df["cwes"] = df["weaknesses"].apply(extract_cwes)


# ─────────────────────────────────────────────
# 5. EXPAND FOR ANALYSIS
# ─────────────────────────────────────────────
exploded = df.explode("cwes")


# ─────────────────────────────────────────────
# 6. PIVOT TABLES
# ─────────────────────────────────────────────

# Project × CWE
pivot_cwe = pd.pivot_table(
    exploded,
    index="project",
    columns="cwes",
    values="id",
    aggfunc="count",
    fill_value=0
)


# Year × Project
pivot_year = pd.pivot_table(
    df,
    index="year",
    columns="project",
    values="id",
    aggfunc="count",
    fill_value=0
)


# CWE frequency per project
cwe_counts = (
    exploded.groupby(["project", "cwes"])
    .size()
    .reset_index(name="count")
    .sort_values("count", ascending=False)
)


# ─────────────────────────────────────────────
# 7. CVSS ANALYSIS
# ─────────────────────────────────────────────

def extract_cvss(metrics):
    if not metrics:
        return None

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics:
            try:
                return metrics[key][0]["cvssData"]["baseScore"]
            except:
                return None
    return None


df["cvss_score"] = df["metrics"].apply(extract_cvss)

risk_by_project = df.groupby("project")["cvss_score"].mean()
severity_dist = df["vulnStatus"].value_counts()


# ─────────────────────────────────────────────
# 8. OUTPUT
# ─────────────────────────────────────────────

print("\n=== PROJECT × CWE ===")
print(pivot_cwe)

print("\n=== EVOLUTION (YEAR × PROJECT) ===")
print(pivot_year)

print("\n=== TOP CWE OCCURRENCES ===")
print(cwe_counts.head(20))

print("\n=== AVG RISK BY PROJECT ===")
print(risk_by_project)

print("\n=== STATUS DISTRIBUTION ===")
print(severity_dist)

analysis_text = []

analysis_text.append("=== TOP CWE OCCURRENCES ===\n")
analysis_text.append(str(cwe_counts.head(20)))

analysis_text.append("\n=== AVG RISK BY PROJECT ===\n")
analysis_text.append(str(risk_by_project))

analysis_text.append("\n=== STATUS DISTRIBUTION ===\n")
analysis_text.append(str(severity_dist))

with open("tables/analysis.txt", "w", encoding="utf-8") as f:
    f.write("\n\n".join(analysis_text))


# ─────────────────────────────────────────────
# 9. SAVE
# ─────────────────────────────────────────────

#  Tabela que relaciona nas linhas o projecto e nas colunas o CWE, sendo q nas celulas aparecem o nº de vulnerabilidades
pivot_cwe.to_csv("tables/pivot_cwe.csv")
# Evolução do nº de vulnerabilidades ao longo do ano
pivot_year.to_csv("tables/pivot_year.csv")
# Contagem de CWES por projeto
cwe_counts.to_csv("tables/cwe_counts.csv", index=False)
# Dataset processado
df.to_csv("tables/cves_processed_full.csv", index=False)