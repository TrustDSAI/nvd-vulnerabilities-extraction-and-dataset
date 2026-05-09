import csv
from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import sys
import os

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
sys.path.append(parent_dir)

try:
    from cve_loader import load_cve_dataset
except ImportError:
    print("error loading cve_loader")


# Path to cwe csv file
file_path = "cwe_summary.csv"
output_file_cwe_filter = "cwe_summary.csv"
output_file_category_count = "category_count_cwe.csv"


##################
# Lê o csv do group by dos CWE's e faz uma filtragem, retirando os CWE's q n interessam e deixando filtros.
##################
def read_and_filter_csv(file_path, output_file, min_value):
    # Dictionary to sum occurrences by CWE
    cwe_counts = defaultdict(int)

    # Reads the CSV, and sums the counts for each CWE
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cwe = row['cwes']
            count = int(row['count'])
            cwe_counts[cwe] += count

    # Filter CWEs with more than 10 occurrences
    doesnt_matter_cwes = [
        "NVD-CWE-Other",
        "NVD-CWE-noinfo",
    ]

    filtered = {}
    for cwe, cnt in cwe_counts.items():
        if cwe in doesnt_matter_cwes:
            continue
        if cnt >= min_value:
            filtered[cwe] = cnt


    # Sort by number of occurrences (descending)
    sorted_cwes = sorted(filtered.items(), key=lambda x: x[1], reverse=True)

    # Print numbered results
    for idx, (cwe, cnt) in enumerate(sorted_cwes, start=1):
        print(f"{idx}. {cwe} - {cnt}")


    # Saves the file with noinfo and other cwes filtered out, and only those with more than 10 occurrences, sorted by count
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['index', 'cwe', 'total_count'])
        
        for idx, (cwe, cnt) in enumerate(sorted_cwes, start=1):
            writer.writerow([idx, cwe, cnt])

    print(f"File saved to: {output_file}")

##################
# Mapeia os CWE's em categorias, para não termos de trabalhar com tantos.
##################
def get_cwe_mapping():
    return {
        "Input Validation": [79, 918, 20, 601, 94, 77, 502, 1284],
        "Permission": [863, 862, 639, 352, 732, 284, 287, 269, 264, 276, 306, 1220],
        "Data Protection": [200, 201, 312],
        "Coding Practices": [770, 1333, 400],
        "File Management": [22],
        "Error Handling and Logging": [532, 209],
        "Output Encoding": [116]
    }

def get_cwe_category(cwe_str, mapping):
    try:
        cwe_id = int(cwe_str.split('-')[-1])
    except (ValueError, IndexError):
        return "Invalid format!"
    
    for category, ids in mapping.items():
        if cwe_id in ids:
            return category
    return "Unmapped"

def count_per_category(file_path, output_file, mapping):
    category_counts = defaultdict(int)

    # Reads the CSV, and sums the counts for each CWE
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cwe_str = row['cwe']
            count = int(row['total_count'])

            category = get_cwe_category(cwe_str, mapping)
            category_counts[category] += count

    sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
    total_geral = sum(category_counts.values())
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Category', 'occurrences', 'percentage'])
        
        for category, total in sorted_categories:
            percentage = (total / total_geral * 100) if total_geral > 0 else 0
            writer.writerow([category, total, f"{percentage:.2f}%"])

        writer.writerow(['Total', total_geral, "100%"])
    
    print(f"File {output_file} saved!")

##################
# Mapeia os CWE's em categorias, para não termos de trabalhar com tantos.
##################

def extract_cwes_list(weaknesses):
    if not weaknesses: return []
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            val = d.get("value", "")
            if "CWE-" in val: cwes.append(val)
    return cwes
    
def generate_top_10_chart_from_files(jenkins_csv, gitlab_csv):
    
    # Dataset read
    df_j = load_cve_dataset(jenkins_csv)
    df_g = load_cve_dataset(gitlab_csv)
    
    df_j["project"] = "jenkins"
    df_g["project"] = "gitlab"
    
    # Dataset merge
    df = pd.concat([df_j, df_g], ignore_index=True)
    
    df["cwes"] = df["weaknesses"].apply(extract_cwes_list)
    exploded = df.explode("cwes")
    
    # Noise removal
    exclude = ["NVD-CWE-noinfo", "NVD-CWE-Other"]
    clean_df = exploded[~exploded["cwes"].isin(exclude)].copy()

    # Top 10 per project
    gitlab_top = clean_df[clean_df["project"] == "gitlab"]["cwes"].value_counts().head(10).reset_index()
    gitlab_top.columns = ["cwe", "count"]
    
    jenkins_top = clean_df[clean_df["project"] == "jenkins"]["cwes"].value_counts().head(10).reset_index()
    jenkins_top.columns = ["cwe", "count"]

    # Graphic
    sns.set_theme(style="whitegrid")
    fig, axes = plt.subplots(1, 2, figsize=(16, 7))

    # Plot GitLab
    sns.barplot(data=gitlab_top, x="count", y="cwe", ax=axes[0], color="#4c72b0")
    axes[0].set_title("Top 10 CWEs: GitLab", fontsize=14, fontweight='bold')
    axes[0].set_xlabel("Occurrences")

    # Plot Jenkins
    sns.barplot(data=jenkins_top, x="count", y="cwe", ax=axes[1], color="#dd8452")
    axes[1].set_title("Top 10 CWEs: Jenkins", fontsize=14, fontweight='bold')
    axes[1].set_xlabel("Occurrences")
    axes[1].set_ylabel("")

    handles = [
        plt.Rectangle((0,0),1,1, color="#4c72b0", label="GitLab"),
        plt.Rectangle((0,0),1,1, color="#dd8452", label="Jenkins")
    ]
    fig.legend(handles=handles, title="Projetos", loc="upper right")
    plt.suptitle("Comparação de CWEs Frequentes (Top 10 por Projeto)", fontsize=16)
    
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    
    output_path = "tables/top_10_comparison.png"
    plt.savefig(output_path, bbox_inches='tight')
    print(f"Gráfico guardado em: {output_path}")
    plt.show()

def main():
    # read_and_filter_csv(file_path, output_file, 10)
    mapping = get_cwe_mapping()
    #count_per_category(file_path, output_file_category_count, mapping)
    
    jenkins_file = "cves_full_jenkins.csv"
    gitlab_file = "cves_full_gitlab.csv"
    
    generate_top_10_chart_from_files(jenkins_file, gitlab_file)

if __name__ == "__main__":
    main()