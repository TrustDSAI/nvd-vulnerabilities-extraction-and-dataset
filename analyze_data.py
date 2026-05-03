import pandas as pd
from cve_loader import load_cve_dataset
import os
import csv
import matplotlib.pyplot as plt
import seaborn as sns

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
    fill_value=0,
    margins=True,
    margins_name="Total"
)


# Year × Project
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

def extract_cvss_detailed(metrics):
    if not metrics:
        return pd.Series([None, None], index=["cvss_score", "cvss_version"])

    # Prioritize 3.1, then 3.0, then 2.0
    for key, version in [("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")]:
        if key in metrics:
            try:
                score = metrics[key][0]["cvssData"]["baseScore"]
                return pd.Series([score, version], index=["cvss_score", "cvss_version"])
            except:
                continue
    return pd.Series([None, None], index=["cvss_score", "cvss_version"])

# Apply and join back to the main dataframe
cvss_data = df["metrics"].apply(extract_cvss_detailed)
df = pd.concat([df, cvss_data], axis=1)

# Now we can analyze meaningfully
# 1. Average score per project, grouped by CVSS version
risk_by_version = df.groupby(["project", "cvss_version"])["cvss_score"].mean().unstack()

# 2. Distribution of versions (to see if your data is mostly old or new)
version_counts = df.groupby("project")["cvss_version"].value_counts().unstack(fill_value=0)

print("\n=== AVG RISK BY CVSS VERSION ===")
print(risk_by_version)

print("\n=== CVSS VERSION DISTRIBUTION BY PROJECT ===")
print(version_counts)

risk_by_version.to_csv("tables/cvss_risk_averages.csv")

# Save the distribution of versions per project
version_counts.to_csv("tables/cvss_version_distribution.csv")

# Save a summary table with ID, Project, Score, and Version for deep-dives
cvss_export = df[["id", "project", "cvss_score", "cvss_version"]]
cvss_export.to_csv("tables/cvss_detailed_scores.csv", index=False)

print("\nCVSS data saved to 'tables/' directory.")


# ─────────────────────────────────────────────
# 8. OUTPUT
# ─────────────────────────────────────────────

print("\n=== PROJECT × CWE ===")
print(pivot_cwe)

print("\n=== EVOLUTION (YEAR × PROJECT) ===")
print(pivot_year)

print("\n=== TOP CWE OCCURRENCES ===")
print(cwe_counts.head(20))

analysis_text = []

analysis_text.append("=== TOP CWE OCCURRENCES ===\n")
analysis_text.append(str(cwe_counts.head(20)))

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

# ─────────────────────────────────────────────
# 10. Mapping by category of CWE.
# ─────────────────────────────────────────────

cwe_mapping = {
    'Identity & Access Management': [
        'CWE-262', 'CWE-264', 'CWE-266', 'CWE-267', 'CWE-268', 'CWE-269', 'CWE-270', 
        'CWE-276', 'CWE-279', 'CWE-281', 'CWE-282', 'CWE-284', 'CWE-285', 'CWE-286', 
        'CWE-287', 'CWE-288', 'CWE-302', 'CWE-305', 'CWE-306', 'CWE-307', 'CWE-384', 
        'CWE-613', 'CWE-639', 'CWE-732', 'CWE-862', 'CWE-863'
    ], 
    'Injection & Input Handling': [
        'CWE-20', 'CWE-74', 'CWE-77', 'CWE-78', 'CWE-79', 'CWE-80', 'CWE-89', 'CWE-93', 
        'CWE-94', 'CWE-99', 'CWE-113', 'CWE-116', 'CWE-117', 'CWE-184', 'CWE-1284', 
        'CWE-1287', 'CWE-1288', 'CWE-1289'
    ], 
    'Information Exposure': [
        'CWE-200', 'CWE-201', 'CWE-203', 'CWE-209', 'CWE-212', 'CWE-213', 'CWE-312', 
        'CWE-359', 'CWE-497', 'CWE-522', 'CWE-532', 'CWE-535', 'CWE-538', 'CWE-540', 
        'CWE-552', 'CWE-922'
    ], 
    'Resource & Memory Mgmt.': [
        'CWE-400', 'CWE-404', 'CWE-407', 'CWE-409', 'CWE-770', 'CWE-772', 'CWE-787', 
        'CWE-789', 'CWE-835'
    ], 
    'Broken Business Logic': [
        'CWE-345', 'CWE-346', 'CWE-350', 'CWE-358', 'CWE-362', 'CWE-367', 'CWE-424', 
        'CWE-425', 'CWE-434', 'CWE-436', 'CWE-441', 'CWE-444', 'CWE-451', 'CWE-459', 
        'CWE-471', 'CWE-502', 'CWE-640', 'CWE-642', 'CWE-668', 'CWE-674', 'CWE-684', 
        'CWE-697', 'CWE-706', 'CWE-708', 'CWE-749', 'CWE-754', 'CWE-755', 'CWE-821', 
        'CWE-829', 'CWE-840', 'CWE-841', 'CWE-843', 'CWE-918', 'CWE-1023', 'CWE-1295'
    ], 
    'Path & File Traversal': [
        'CWE-22', 'CWE-23', 'CWE-27', 'CWE-377', 'CWE-59'
    ], 
    'Configuration & UI': [
        'CWE-16', 'CWE-17', 'CWE-451', 'CWE-601', 'CWE-1021'
    ], 
    'Cryptography': [
        'CWE-250', 'CWE-252', 'CWE-254', 'CWE-290', 'CWE-295', 'CWE-310', 'CWE-319', 
        'CWE-325', 'CWE-326', 'CWE-327', 'CWE-330', 'CWE-347', 'CWE-798'
    ], 
    'Miscellaneous & Unmapped': [
        'CWE-1220', 'CWE-1333', 'CWE-1390', 'CWE-177', 'CWE-233', 'CWE-352', 
        'CWE-399', 'CWE-565', 'CWE-90', 'NVD-CWE-Other', 'NVD-CWE-noinfo'
    ]
}
def get_category(cwe_label):
    if "noinfo" in cwe_label or "Other" in cwe_label:
        return "Unmapped CWEs"
    
    for category, cwes in cwe_mapping.items():
        if cwe_label in cwes:
            return category
    return "Unmapped CWEs"

def process_csv(input_file, output_file):
    with open(input_file, mode='r', encoding='utf-8') as infile:
        reader = csv.reader(infile)
        header = next(reader)
        
        # New header
        header.append("category")
        
        results = [header]
        for row in reader:
            if not row: continue
            project, cwe, count = row
            category = get_category(cwe)
            row.append(category)
            results.append(row)

    with open(output_file, mode='w', encoding='utf-8', newline='') as outfile:
        writer = csv.writer(outfile)
        writer.writerows(results)

process_csv('tables/cwe_counts.csv', 'tables/cwe_category_mapping.csv')

# ─────────────────────────────────────────────
# 11. Pivot table with project / vulnerability categories
# ─────────────────────────────────────────────

# Create an inverse mapping for faster lookup: { 'CWE-79': 'Injection & Input Handling', ... }
inverse_mapping = {cwe: cat for cat, cwes in cwe_mapping.items() for cwe in cwes}

# Map the exploded CWEs to their respective categories
exploded['category'] = exploded['cwes'].map(lambda x: inverse_mapping.get(x, 'Miscellaneous & Unmapped'))

# Generate the pivot table
# Project on Y-axis (index), Category on X-axis (columns)
pivot_category = pd.pivot_table(
    exploded,
    index="project",
    columns="category",
    values="id",
    aggfunc="count",
    fill_value=0
)

# Add Totals for easier analysis
pivot_category_with_totals = pd.pivot_table(
    exploded,
    index="project",
    columns="category",
    values="id",
    aggfunc="count",
    fill_value=0,
    margins=True,
    margins_name="Total"
)

print("\n=== PROJECT × VULNERABILITY CATEGORY ===")
print(pivot_category_with_totals)

# Save the final table
pivot_category_with_totals.to_csv("tables/pivot_category.csv")

# Set visual style
sns.set_theme(style="whitegrid")

# --- Chart 1: Heatmap of Categories ---
# We use the version without totals for the heatmap to avoid skewing the colors
plt.figure(figsize=(12, 6))
sns.heatmap(pivot_category, annot=True, fmt='g', cmap='YlGnBu', cbar_kws={'label': 'Count'})
plt.title('Vulnerability Categories by Project')
plt.ylabel('Project')
plt.xlabel('Category')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig("tables/heatmap_categories.png")
plt.show()

# --- Chart 2: Evolution over Years ---
# Plotting the pivot_year (excluding the 'Total' row/column if you added them)
plot_year_df = pivot_year.drop('Total', axis=0, errors='ignore').drop('Total', axis=1, errors='ignore')

plt.figure(figsize=(10, 6))
plot_year_df.plot(kind='line', marker='o')
plt.title('Vulnerability Evolution per Year')
plt.ylabel('Number of Vulnerabilities')
plt.xlabel('Year')
plt.grid(True, linestyle='--', alpha=0.7)
plt.tight_layout()
plt.savefig("tables/evolution_plot.png")
plt.show()

# --- Chart 3: Top 10 CWEs (Bar Chart) ---
plt.figure(figsize=(10, 6))
top_10_cwes = cwe_counts.head(10)
sns.barplot(data=top_10_cwes, x='count', y='cwes', hue='project')
plt.title('Top 10 Most Frequent CWEs')
plt.tight_layout()
plt.savefig("tables/top_cwes_bar.png")
plt.show()

# CVSS Distribution
plt.figure(figsize=(10, 6))
sns.boxplot(data=df.dropna(subset=['cvss_score']), x='cvss_version', y='cvss_score', hue='project')
plt.title('CVSS Score Distribution by Version and Project')
plt.ylim(0, 10)
plt.savefig("tables/cvss_boxplot.png")
plt.show()