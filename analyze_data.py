import pandas as pd
from cve_loader import load_cve_dataset
import os
import csv
import matplotlib.pyplot as plt
import seaborn as sns
import json

OUTPUT_DIR = "data/data analysis"

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
        "data/datasets/cves_full_argo_cd.csv",
        "data/datasets/cves_full_azure_devops.csv",
        "data/datasets/cves_full_bamboo.csv",
        "data/datasets/cves_full_bitbucket.csv",
        "data/datasets/cves_full_github.csv",
        "data/datasets/cves_full_gitlab.csv",
        "data/datasets/cves_full_jenkins.csv",
        "data/datasets/cves_full_teamcity.csv",
        "data/datasets/cves_full_tekton.csv",
        "data/datasets/cves_full_travis_ci.csv"
    ]

    projects = [
        "argo_cd",
        "azure_devops",
        "bamboo",
        "bitbucket",
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

def save_data(output_path="data/datasets/cves_merged.csv"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    df = load_data()
    
    df.to_csv(output_path, index=False)
    
    print(f"Dataset saved to: {output_path}")

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
    plt.savefig("data/data analysis/evolution_plot.png")
    plt.show()

    # Top CWEs
    plt.figure(figsize=(10, 6))
    sns.barplot(data=cwe_counts.head(10), x='count', y='cwes', hue='project')
    plt.savefig("data/data analysis/top_cwes_bar.png")
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
    plt.savefig("data/data analysis/cvss_boxplot.png")
    plt.show()

# ─────────────────────────────────────────────
# EXTRA: COMMIT ANALYSIS
# ─────────────────────────────────────────────
def extract_commits(refs):
    """
    Extrai URLs únicos de commits a partir das referências de um CVE.
    """
    commits = set()
    
    # Se a referência vier como string (JSON), tenta convertê-la para lista
    if isinstance(refs, str):
        try:
            refs = json.loads(refs)
        except json.JSONDecodeError:
            return commits

    # Verifica se as referências são uma lista válida após a conversão
    if not isinstance(refs, list):
        return commits
        
    for ref in refs:
        url = ""
        if isinstance(ref, dict):
            url = ref.get("url", "")
        elif isinstance(ref, str):
            url = ref
            
        # Verifica se é um link de commit
        if url and "/commit/" in url:
            commits.add(url.strip())
            
    return commits


def analyze_commits_per_project(df):
    """
    Analisa as referências para contar os commits únicos por projeto,
    detalhando a distribuição do número de commits por CVE e adicionando
    uma linha de total.
    """
    results = []
    
    # Agrupa por projeto para fazer a contagem
    for project, group in df.groupby("project"):
        total_cves = len(group)
        
        # Contadores para as novas colunas
        cves_sem_commit = 0
        cves_um_commit = 0
        cves_multiplos_commits = 0
        
        unique_commits_total = set()
        
        for refs in group["references"]:
            # Extrai os commits deste CVE específico
            commits_in_cve = extract_commits(refs)
            num_commits_in_cve = len(commits_in_cve)
            
            # Distribui pelas novas categorias
            if num_commits_in_cve == 0:
                cves_sem_commit += 1
            elif num_commits_in_cve == 1:
                cves_um_commit += 1
            else:
                cves_multiplos_commits += 1
                
            # Adiciona os commits ao total do projeto
            unique_commits_total.update(commits_in_cve)
            
        num_unique_commits = len(unique_commits_total)
        
        # Calcula a percentagem (Unique Commits / Total CVEs)
        percentage = (num_unique_commits / total_cves * 100) if total_cves > 0 else 0
        
        results.append({
            "Project": project,
            "Total CVEs": total_cves,
            "Unique Commits": num_unique_commits,
            "Commit %": round(percentage, 2),
            "CVEs s/ Commit": cves_sem_commit,
            "CVEs c/ 1 Commit": cves_um_commit,
            "CVEs c/ >1 Commit": cves_multiplos_commits
        })

    # Converte os resultados num DataFrame
    df_commits = pd.DataFrame(results)
    
    # Ordena pelo número de commits únicos em ordem decrescente
    df_commits = df_commits.sort_values(by="Unique Commits", ascending=False)
    
    # --- LÓGICA DA LINHA DE TOTAL ---
    total_cves_all = df_commits["Total CVEs"].sum()
    total_commits_all = df_commits["Unique Commits"].sum()
    total_percent = (total_commits_all / total_cves_all * 100) if total_cves_all > 0 else 0
    
    total_row = pd.DataFrame([{
        "Project": "Total",
        "Total CVEs": total_cves_all,
        "Unique Commits": total_commits_all,
        "Commit %": round(total_percent, 2),
        "CVEs s/ Commit": df_commits["CVEs s/ Commit"].sum(),
        "CVEs c/ 1 Commit": df_commits["CVEs c/ 1 Commit"].sum(),
        "CVEs c/ >1 Commit": df_commits["CVEs c/ >1 Commit"].sum()
    }])
    
    # Anexa a linha de total ao DataFrame existente
    df_commits = pd.concat([df_commits, total_row], ignore_index=True)
    
    # Guarda o resultado num ficheiro CSV
    output_path = f"{OUTPUT_DIR}/commits_per_project.csv"
    df_commits.to_csv(output_path, index=False)
    
    print("\n--- Análise de Commits por Projeto ---")
    print(df_commits.to_string(index=False))
    print(f"\nResultados guardados em: {output_path}\n")
    
    return df_commits

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    setup()

    #save_data()
    df = load_data()
    df = feature_engineering(df)

    df_commits = analyze_commits_per_project(df)

    #exploded, pivot_cwe, pivot_year, cwe_counts = create_analysis_tables(df)

    #cvss_analysis(df)
    #save_tables(df, pivot_cwe, pivot_year, cwe_counts)

    #generate_plots(pivot_year, cwe_counts, df)


if __name__ == "__main__":
    main()