import csv
import os
from pathlib import Path
import sys
from collections import defaultdict

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import pandas as pd
import seaborn as sns

PROJECT_ROOT = Path(r"C:\Users\João Ferreira\Desktop\Projetos\investigacao-2526\25-26\TrustDevSecAI\nvd-vulnerabilities-extraction-and-dataset")
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

from cve_loader import load_cve_dataset  # falha logo se o módulo não existir

# ── Constantes ─────────────────────────────────────────────────────────────────
NEW_DATASET = "data/new_datasets/dataset_cve.csv"
OUTPUT_DIR = "data/new_datasets/data_analysis"
CWE_DIR = f"{OUTPUT_DIR}/cwe_analysis"

# gerado pelo script de análise principal (group by projeto/CWE)
CWE_COUNTS_CSV = f"{OUTPUT_DIR}/cwe_counts.csv"
CWE_SUMMARY_CSV = f"{CWE_DIR}/cwe_summary.csv"
CATEGORY_COUNT_CSV = f"{CWE_DIR}/category_count_cwe.csv"
CWE_TOTAL_GLOBAL_CSV = f"{CWE_DIR}/cwe_total_global.csv"

EXCLUDE_CWES = ["NVD-CWE-noinfo", "NVD-CWE-Other"]
EXCLUDED_PROJECTS = ["tekton", "travis_ci", "bamboo", "bitbucket"]  # fora do top 10


# ── Mapeamento CWE -> categoria ────────────────────────────────────────────────
def get_cwe_mapping():
    """Mapeia os CWEs (com 10 ou mais ocorrências) em categorias."""
    return {
        "Input Validation": [79, 918, 20, 77, 601, 94, 502, 78, 1284, 88],
        "Permission": [863, 862, 639, 352, 284, 287, 732, 269, 276, 306, 613, 264, 288, 285, 1220],
        "Data Protection": [200, 201, 522, 312, 295],
        "Coding Practices": [770, 1333, 400, 367, 697, 835],
        "File Management": [22, 23],
        "Error Handling and Logging": [532, 209],
        "Output Encoding": [116],
        "System Configuration": [59],
    }


def get_cwe_category(cwe_str, mapping):
    try:
        cwe_id = int(cwe_str.split("-")[-1])
    except (ValueError, IndexError, AttributeError):
        if cwe_str not in EXCLUDE_CWES:  # evita ruído no log com os NVD-CWE-*
            print(f"CWE-STR Invalid format: {cwe_str}")
        return "Invalid format!"

    for category, ids in mapping.items():
        if cwe_id in ids:
            return category
    return "Unmapped"


def extract_cwes_list(weaknesses):
    if not weaknesses:
        return []
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            val = d.get("value", "")
            if "CWE-" in val:
                cwes.append(val)
    return cwes


# ── Carregar dados ─────────────────────────────────────────────────────────────
def load_data() -> pd.DataFrame:
    df = load_cve_dataset(NEW_DATASET)
    df = df.drop_duplicates(subset=["id"]).copy()
    df["year"] = pd.to_datetime(df["published"], errors="coerce").dt.year
    df["cwes"] = df["weaknesses"].apply(extract_cwes_list)
    return df


# ── Análise a partir do cwe_counts.csv ─────────────────────────────────────────
def read_and_filter_csv(file_path, output_file, min_value):
    """Soma as ocorrências por CWE, tira as NVD-CWE-* e guarda as que têm >= min_value."""
    cwe_counts = defaultdict(int)

    with open(file_path, newline="", encoding="utf-8") as csvfile:
        for row in csv.DictReader(csvfile):
            cwe_counts[row["cwes"]] += int(row["count"])

    filtered = {
        cwe: cnt for cwe, cnt in cwe_counts.items()
        if cwe not in EXCLUDE_CWES and cnt >= min_value
    }
    sorted_cwes = sorted(filtered.items(), key=lambda x: x[1], reverse=True)

    for idx, (cwe, cnt) in enumerate(sorted_cwes, start=1):
        print(f"{idx}. {cwe} - {cnt}")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["index", "cwes", "count"])
        for idx, (cwe, cnt) in enumerate(sorted_cwes, start=1):
            writer.writerow([idx, cwe, cnt])

    print(f"File saved to: {output_file}")


def count_per_category(file_path, output_file, mapping):
    category_counts = defaultdict(int)

    with open(file_path, newline="", encoding="utf-8") as csvfile:
        for row in csv.DictReader(csvfile):
            category = get_cwe_category(row["cwes"], mapping)
            category_counts[category] += int(row["count"])

    sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
    total_geral = sum(category_counts.values())

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Category", "occurrences", "percentage"])
        for category, total in sorted_categories:
            pct = (total / total_geral * 100) if total_geral > 0 else 0
            writer.writerow([category, total, f"{pct:.2f}%"])
        writer.writerow(["Total", total_geral, "100%"])

    print(f"File {output_file} saved!")


def calculate_global_cwe_counts_with_report(input_csv_path, output_csv_path):
    print("\n--- Calculating global CWE totals and reporting low-frequency items ---")

    cwe_totals = defaultdict(int)

    try:
        with open(input_csv_path, mode="r", newline="", encoding="utf-8") as csvfile:
            for row in csv.DictReader(csvfile):
                if row["project"] == "Total":
                    continue
                cwe_totals[row["cwes"]] += int(row["count"])
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    less_than_10_count = 0
    less_than_10_names = []
    for cwe, total in cwe_totals.items():
        if total < 10 and cwe not in EXCLUDE_CWES:
            less_than_10_count += total
            less_than_10_names.append(cwe)

    print("\n--- Statistics for CWEs with < 10 occurrences ---")
    print(f"Total occurrences (excluding noise): {less_than_10_count}")
    print(f"Number of distinct CWE types found with < 10 occurrences: {len(less_than_10_names)}")
    print(f"Types found: {', '.join(less_than_10_names)}")

    sorted_all = sorted(cwe_totals.items(), key=lambda x: x[1], reverse=True)

    try:
        os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
        with open(output_csv_path, mode="w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["cwe", "total_count"])
            writer.writerows(sorted_all)
            writer.writerow(["Total", sum(cwe_totals.values())])
        print(f"\nSuccess! Full CWE totals saved to: {output_csv_path}")
    except Exception as e:
        print(f"Error saving file: {e}")


# ── Classificação dos CVEs por categoria ───────────────────────────────────────
def count_cves_per_category_and_export_conflicts(df, output_conflicts_csv, output_summary_csv):
    """
    Conta CVEs únicos por categoria, só para CVEs cujos CWEs pertencem a uma única categoria.

    Casos:
    1. Puro: todos os CWEs mapeados e da MESMA categoria -> conta para essa categoria
    2. Conflito: todos mapeados mas de categorias DIFERENTES -> CSV de conflitos
    3. Sem mapeamento: pelo menos um CWE sem mapeamento (ou formato inválido) -> CSV de unmapped
    4. Só excluídos: apenas NVD-CWE-noinfo / NVD-CWE-Other (ou sem CWEs) -> CSV de excluídos
    """
    mapping = get_cwe_mapping()

    category_cves = defaultdict(list)
    conflict_cves = []
    unmapped_cves = []
    excluded_only_cves = []

    total_cves_processed = 0
    total_pure_cves = 0
    unmapped_cwe_count = 0
    unmapped_cwe_set = set()
    noinfo_count = 0
    other_count = 0

    for project_name, df_proj in df.groupby("project"):
        for _, row in df_proj.iterrows():
            cve_id = str(row["id"])
            cwe_list = row["cwes"]
            total_cves_processed += 1

            noinfo_count += cwe_list.count("NVD-CWE-noinfo")
            other_count += cwe_list.count("NVD-CWE-Other")

            categories_for_cve = set()
            unmapped_cwes_in_cve = []
            mapped_cwes_in_cve = []

            for cwe in cwe_list:
                if cwe in EXCLUDE_CWES:
                    continue

                category = get_cwe_category(cwe, mapping)
                if category in ("Unmapped", "Invalid format!"):
                    unmapped_cwes_in_cve.append(cwe)
                    unmapped_cwe_count += 1
                    unmapped_cwe_set.add(cwe)
                else:
                    mapped_cwes_in_cve.append(cwe)
                    categories_for_cve.add(category)

            # CASO 4: só CWEs excluídos (ou nenhum CWE)
            if not mapped_cwes_in_cve and not unmapped_cwes_in_cve:
                excluded_only_cves.append({
                    "project": project_name,
                    "cve_id": cve_id,
                    "cwes": ", ".join(cwe_list) if cwe_list else "No CWEs",
                })
                continue

            # CASO 3: pelo menos um CWE sem mapeamento
            if unmapped_cwes_in_cve:
                unmapped_cves.append({
                    "project": project_name,
                    "cve_id": cve_id,
                    "all_cwes": ", ".join(cwe_list),
                    "mapped_cwes": ", ".join(mapped_cwes_in_cve) if mapped_cwes_in_cve else "None",
                    "unmapped_cwes": ", ".join(unmapped_cwes_in_cve),
                    "categories_found": ", ".join(sorted(categories_for_cve)) if categories_for_cve else "None",
                })
                continue

            # CASOS 1 e 2: tudo mapeado
            if len(categories_for_cve) == 1:
                total_pure_cves += 1
                category_cves[next(iter(categories_for_cve))].append(cve_id)
            else:
                conflict_cves.append({
                    "project": project_name,
                    "cve_id": cve_id,
                    "cwes": ", ".join(mapped_cwes_in_cve),
                    "categories": ", ".join(sorted(categories_for_cve)),
                    "num_categories": len(categories_for_cve),
                })

    total_conflict_cves = len(conflict_cves)
    total_unmapped_cves = len(unmapped_cves)
    total_excluded_only_cves = len(excluded_only_cves)

    print(f"\n{'=' * 70}")
    print("CATEGORY COUNTING STATISTICS (By CVE Classification)")
    print(f"{'=' * 70}")
    print("\n--- CVE Processing Summary ---")
    print(f"Total CVEs processed: {total_cves_processed}")
    print(f"\n  CASE 1 - Pure CVEs (mapped, single category): {total_pure_cves}")
    print(f"  CASE 2 - Conflict CVEs (mapped, multiple categories): {total_conflict_cves}")
    print(f"  CASE 3 - Unmapped CVEs (at least one unmapped CWE): {total_unmapped_cves}")
    print(f"  CASE 4 - Excluded-only CVEs (only NVD-CWE-noinfo/Other): {total_excluded_only_cves}")

    calculated_total = total_pure_cves + total_conflict_cves + total_unmapped_cves + total_excluded_only_cves
    if calculated_total != total_cves_processed:
        print(f"\n⚠️ WARNING: Sum mismatch! {calculated_total} vs {total_cves_processed}")
    else:
        print(f"\n✓ Sum verification: {calculated_total} = {total_cves_processed}")

    if total_cves_processed > 0:
        print("\n--- Percentages ---")
        print(f"  Pure CVEs: {total_pure_cves / total_cves_processed * 100:.2f}%")
        print(f"  Conflict CVEs: {total_conflict_cves / total_cves_processed * 100:.2f}%")
        print(f"  Unmapped CVEs: {total_unmapped_cves / total_cves_processed * 100:.2f}%")
        print(f"  Excluded-only CVEs: {total_excluded_only_cves / total_cves_processed * 100:.2f}%")

    print("\n--- Unmapped CWE Statistics ---")
    print(f"Unmapped CWE occurrences: {unmapped_cwe_count}")
    print(f"Unique unmapped CWE types: {len(unmapped_cwe_set)}")
    if unmapped_cwe_set:
        print(f"Unmapped CWE types: {', '.join(sorted(unmapped_cwe_set))}")

    print("\n--- Excluded CWE Statistics ---")
    print(f"NVD-CWE-noinfo occurrences: {noinfo_count}")
    print(f"NVD-CWE-Other occurrences: {other_count}")
    print(f"Total excluded occurrences: {noinfo_count + other_count}")

    os.makedirs(os.path.dirname(output_conflicts_csv), exist_ok=True)

    def _write(rows, path, fieldnames, label):
        if not rows:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"{label}: {path} ({len(rows)} CVEs)")

    print("\n--- File Output ---")
    _write(conflict_cves, output_conflicts_csv,
           ["project", "cve_id", "cwes", "categories", "num_categories"],
           "Conflicts file (Case 2)")
    _write(unmapped_cves, output_conflicts_csv.replace(".csv", "_unmapped_cves.csv"),
           ["project", "cve_id", "all_cwes", "mapped_cwes", "unmapped_cwes", "categories_found"],
           "Unmapped CVEs file (Case 3)")
    _write(excluded_only_cves, output_conflicts_csv.replace(".csv", "_excluded_only.csv"),
           ["project", "cve_id", "cwes"],
           "Excluded-only CVEs file (Case 4)")

    export_category_summary(category_cves, output_summary_csv, total_pure_cves)

    return category_cves, conflict_cves, unmapped_cves, excluded_only_cves


def export_category_summary(category_cves, output_csv_path, total_cves):
    """Exporta o número de CVEs puros por categoria, com a linha de total no fim."""
    sorted_categories = sorted(category_cves.items(), key=lambda x: len(x[1]), reverse=True)

    os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
    with open(output_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Category", "unique_cves", "percentage"])
        for category, cve_list in sorted_categories:
            count = len(cve_list)
            pct = (count / total_cves * 100) if total_cves > 0 else 0
            writer.writerow([category, count, f"{pct:.2f}%"])
        writer.writerow(["TOTAL", total_cves, "100%"])

    print(f"\nCategory summary saved to: {output_csv_path}")
    print(f"Total pure CVEs (Case 1): {total_cves}")

    if total_cves > 0:
        print("\n--- Category Summary (Pure CVEs Only - Case 1) ---")
        for category, cve_list in sorted_categories:
            count = len(cve_list)
            print(f"  {category}: {count} CVEs ({count / total_cves * 100:.2f}%)")


def export_cves_with_multiple_categories(df: pd.DataFrame, output_csv_path: str) -> None:
    print(f"\n--- Exporting CVEs with multiple categories to {output_csv_path} ---")
    mapping = get_cwe_mapping()

    def unique_categories(cwe_list):
        cats = {get_cwe_category(c, mapping) for c in cwe_list if c not in EXCLUDE_CWES}
        return sorted(cats - {"Invalid format!", "Unmapped"})

    work = df[["id", "project", "cwes"]].copy()
    work["categories"] = work["cwes"].apply(unique_categories)
    multi = work[work["categories"].apply(len) > 1]

    out = pd.DataFrame({
        "project": multi["project"],
        "cve_id": multi["id"],
        "cwes": multi["cwes"].apply(lambda lst: ", ".join(c for c in lst if c not in EXCLUDE_CWES)),
        "categories": multi["categories"].apply(", ".join),
    })

    os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
    out.to_csv(output_csv_path, index=False)
    print(f"Success! {len(out)} records were saved to: {output_csv_path}")


# ── Gráfico: Top 10 CWEs por projeto ───────────────────────────────────────────
def _top10_with_others(counts: pd.Series):
    top = counts.head(10)
    labels, values = list(top.index), list(top.values)
    others = counts.iloc[10:].sum()
    if others > 0:
        labels.append("Others")
        values.append(others)
    return labels, values


def generate_top_10_chart(df: pd.DataFrame) -> None:
    projects = [p for p in sorted(df["project"].dropna().unique()) if p not in EXCLUDED_PROJECTS]
    if not projects:
        print("No projects to plot.")
        return

    clean_df = df.explode("cwes").dropna(subset=["cwes"])
    clean_df = clean_df[~clean_df["cwes"].isin(EXCLUDE_CWES)]

    data = {
        p: _top10_with_others(clean_df.loc[clean_df["project"] == p, "cwes"].value_counts())
        for p in projects
    }
    x_limit = max((max(v) for _, v in data.values() if v), default=1) * 1.15

    cols = 3
    rows = (len(projects) + cols - 1) // cols
    sns.set_theme(style="whitegrid")
    fig, axes = plt.subplots(rows, cols, figsize=(18, 5 * rows))
    axes = axes.flatten()
    palette = sns.color_palette("tab10", n_colors=len(projects))

    for ax, project, color in zip(axes, projects, palette):
        labels, values = data[project]
        if labels:
            colors = [color] * len(labels)
            if labels[-1] == "Others":
                colors[-1] = "lightgray"
            ax.barh(labels, values, color=colors)
            ax.invert_yaxis()
            ax.bar_label(ax.containers[0], padding=3, fontweight="bold", fontsize=10)
        else:
            ax.text(0.5, 0.5, "No Data / No CWEs", ha="center", va="center",
                    transform=ax.transAxes, color="gray")
        ax.set_xlim(0, x_limit)
        ax.set_title(f"Top 10 CWEs: {project}", fontsize=14, fontweight="bold")
        ax.set_xlabel("Occurrences")

    for ax in axes[len(projects):]:
        fig.delaxes(ax)

    handles = [plt.Rectangle((0, 0), 1, 1, color=c, label=p) for p, c in zip(projects, palette)]
    handles.append(plt.Rectangle((0, 0), 1, 1, color="lightgray", label="Others"))
    fig.legend(handles=handles, title="Projects", loc="upper right", bbox_to_anchor=(1.1, 0.62))

    plt.tight_layout()
    output_path = f"{CWE_DIR}/top_10_comparison.pdf"
    os.makedirs(CWE_DIR, exist_ok=True)
    plt.savefig(output_path, bbox_inches="tight")
    print(f"Graphic saved to: {output_path}")
    plt.show()


# ── Heatmaps e áreas empilhadas ────────────────────────────────────────────────
def _save(fig: plt.Figure, filename: str, output_dir: str = CWE_DIR) -> None:
    os.makedirs(CWE_DIR, exist_ok=True)
    path = os.path.join(CWE_DIR, filename)
    fig.savefig(path, bbox_inches="tight")
    print(f"Saved: {path}")
    plt.show()


def plot_heatmap_year_category(df: pd.DataFrame) -> None:
    pivot = df.groupby(["year", "category"]).size().unstack(fill_value=0).sort_index()
    fig, ax = plt.subplots(figsize=(14, 5))
    sns.heatmap(pivot.T, annot=True, fmt="d", cmap="Blues", linewidths=0.4, ax=ax)
    ax.set_title("Vulnerabilities per Year × Category", fontsize=14, fontweight="bold")
    ax.set_xlabel("Year")
    ax.set_ylabel("Category")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    _save(fig, "heatmap_year_category.png")


def plot_heatmap_year_project(df: pd.DataFrame) -> None:
    pivot = df.groupby(["year", "project"]).size().unstack(fill_value=0).sort_index()
    fig, ax = plt.subplots(figsize=(14, 5))
    sns.heatmap(pivot.T, annot=True, fmt="d", cmap="Blues", linewidths=0.4, ax=ax)
    ax.set_title("Vulnerabilities per Year × Project", fontsize=14, fontweight="bold")
    ax.set_xlabel("Year")
    ax.set_ylabel("Project")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    _save(fig, "heatmap_year_project.png")


def plot_heatmap_project_category(df: pd.DataFrame) -> None:
    pivot = df.groupby(["project", "category"]).size().unstack(fill_value=0)
    fig, ax = plt.subplots(figsize=(12, 6))
    sns.heatmap(pivot, annot=True, fmt="d", cmap="Blues", linewidths=0.4, ax=ax)
    ax.set_title("Vulnerabilities per Project × Category", fontsize=14, fontweight="bold")
    ax.set_xlabel("Category")
    ax.set_ylabel("Project")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    _save(fig, "heatmap_project_category.png")


def plot_area_category(df: pd.DataFrame) -> None:
    df_plot = df.copy()
    agrupar = ["System Configuration", "Output Encoding", "Error Handling and Logging", "File Management"]
    df_plot.loc[df_plot["category"].isin(agrupar), "category"] = "Others"

    pivot = df_plot.groupby(["year", "category"]).size().unstack(fill_value=0).sort_index()

    fig, ax = plt.subplots(figsize=(14, 6))
    pivot.plot.area(ax=ax, colormap="tab10", alpha=0.85)
    ax.set_title("Vulnerability Trends by Category (Stacked Area)", fontsize=14, fontweight="bold")
    ax.set_xlabel("Year")
    ax.set_ylabel("CVE Count")
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.legend(title="Category", bbox_to_anchor=(1.01, 1), loc="upper left")
    plt.tight_layout()
    _save(fig, "area_category.pdf")


def plot_area_project(df: pd.DataFrame) -> None:
    df_plot = df.copy()
    agrupar = ["bamboo", "tekton", "travis_ci"]
    df_plot.loc[df_plot["project"].isin(agrupar), "project"] = "Others"

    pivot = df_plot.groupby(["year", "project"]).size().unstack(fill_value=0).sort_index()

    fig, ax = plt.subplots(figsize=(14, 6))
    pivot.plot.area(ax=ax, colormap="tab10", alpha=0.85)
    ax.set_title("Vulnerability Trends by Project (Stacked Area)", fontsize=14, fontweight="bold")
    ax.set_xlabel("Year")
    ax.set_ylabel("CVE Count")
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.legend(title="Project", bbox_to_anchor=(1.01, 1), loc="upper left")
    plt.tight_layout()
    _save(fig, "area_project_grouped.pdf")


def generate_temporal_and_category_charts(df: pd.DataFrame) -> None:
    mapping = get_cwe_mapping()

    exploded = df.explode("cwes").dropna(subset=["cwes", "year"])
    exploded = exploded[~exploded["cwes"].isin(EXCLUDE_CWES)].copy()
    exploded["category"] = exploded["cwes"].apply(lambda x: get_cwe_category(x, mapping))
    exploded = exploded[~exploded["category"].isin(["Invalid format!", "Unmapped"])]

    # um CVE conta uma vez por (projeto, categoria), mesmo com várias CWEs da mesma categoria
    master_df = exploded[["id", "project", "year", "category"]].drop_duplicates()
    master_df["year"] = master_df["year"].astype(int)

    if master_df.empty:
        print("No data for temporal charts.")
        return

    plot_heatmap_year_category(master_df)
    plot_heatmap_year_project(master_df)
    plot_heatmap_project_category(master_df)
    plot_area_category(master_df)
    plot_area_project(master_df)


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    os.makedirs(CWE_DIR, exist_ok=True)
    df = load_data()
    print(f"Loaded {len(df)} CVEs from {NEW_DATASET}")

    read_and_filter_csv(CWE_COUNTS_CSV, CWE_SUMMARY_CSV, 10)
    count_per_category(CWE_SUMMARY_CSV, CATEGORY_COUNT_CSV, get_cwe_mapping())
    calculate_global_cwe_counts_with_report(CWE_COUNTS_CSV, CWE_TOTAL_GLOBAL_CSV)

    generate_top_10_chart(df)
    generate_temporal_and_category_charts(df)
    export_cves_with_multiple_categories(df, f"{CWE_DIR}/multiple_categories_cves.csv")

    count_cves_per_category_and_export_conflicts(
        df,
        f"{CWE_DIR}/cve_category_conflicts.csv",
        f"{CWE_DIR}/cve_category_summary.csv",
    )


if __name__ == "__main__":
    main()