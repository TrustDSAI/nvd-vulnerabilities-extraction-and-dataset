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
file_path = "data/data analysis/cwe_analysis/cwe_counts.csv"
output_file_cwe_filter = "data/data analysis/cwe_analysis/cwe_summary.csv"
output_file_category_count = "data/data analysis/cwe_analysis/category_count_cwe.csv"


##################F
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
        writer.writerow(['index', 'cwes', 'count'])
        
        for idx, (cwe, cnt) in enumerate(sorted_cwes, start=1):
            writer.writerow([idx, cwe, cnt])

    print(f"File saved to: {output_file}")

##################
# Mapeia os CWE's em categorias, para não termos de trabalhar com tantos.
##################
def get_cwe_mapping():
    return {
        "Input Validation": [79, 918, 20, 601, 94, 77, 502, 1284, 78],
        "Permission": [863, 862, 639, 352, 732, 284, 287, 269, 264, 276, 306, 1220, 613, 285, 288],
        "Data Protection": [200, 201, 312, 522, 295],
        "Coding Practices": [770, 1333, 400, 407, 367, 697],
        "File Management": [22, 23],
        "Error Handling and Logging": [532, 209],
        "Output Encoding": [116],
        "System Configuration": [59]
    }



def get_cwe_category(cwe_str, mapping):
    try:
        cwe_id = int(cwe_str.split('-')[-1])
    except (ValueError, IndexError):
        print(f"CWE-STR Invalid format: {cwe_str}")
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
            cwe_str = row['cwes']
            count = int(row['count'])

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
    
def generate_top_10_chart_from_files(files_list, projects_list):
    # 1. Load and concatenate all datasets dynamically
    dfs = []
    for file_path, project_name in zip(files_list, projects_list):
        try:
            df_temp = load_cve_dataset(file_path)
            df_temp["project"] = project_name
            dfs.append(df_temp)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            continue
            
    if not dfs:
        print("No data was successfully loaded.")
        return

    df = pd.concat(dfs, ignore_index=True)
    
    # Extract CWEs and explode the lists
    df["cwes"] = df["weaknesses"].apply(extract_cwes_list)
    exploded = df.explode("cwes")
    
    # Noise removal
    exclude = ["NVD-CWE-noinfo", "NVD-CWE-Other"]
    clean_df = exploded[~exploded["cwes"].isin(exclude)].copy()

    # --- NEW: Find global maximum count to standardize the X-axis ---
    max_x_count = 0
    for project_name in projects_list:
        proj_counts = clean_df[clean_df["project"] == project_name]["cwes"].value_counts().head(10)
        if not proj_counts.empty:
            max_x_count = max(max_x_count, proj_counts.max())
            
    # Add a 5% padding so the largest bar doesn't touch the edge of the plot
    x_limit = max_x_count * 1.05 
    # ----------------------------------------------------------------

    # 2. Configure the subplot grid (e.g., 3x3 for 9 projects)
    num_projects = len(projects_list)
    cols = 3  # Adjust the number of columns you prefer side-by-side
    rows = (num_projects + cols - 1) // cols  # Calculate required rows
    
    sns.set_theme(style="whitegrid")
    # Adjust total figure height based on the number of rows
    fig, axes = plt.subplots(rows, cols, figsize=(18, 5 * rows))
    axes = axes.flatten()  # Flatten to a 1D array for easy iteration

    # Generate a color palette based on the number of projects
    palette = sns.color_palette("tab10", n_colors=num_projects)
    handles = []

    # 3. Iterate over each project and plot its respective bar chart
    for i, project_name in enumerate(projects_list):
        ax = axes[i]
        color = palette[i]
        
        # Filter current project data and extract Top 10
        proj_data = clean_df[clean_df["project"] == project_name]
        top_cwes = proj_data["cwes"].value_counts().head(10).reset_index()
        top_cwes.columns = ["cwe", "count"]
        
        if not top_cwes.empty:
            sns.barplot(data=top_cwes, x="count", y="cwe", ax=ax, color=color)
            
            # --- NEW: Apply the same X-axis limit to all subplots ---
            ax.set_xlim(0, x_limit)
            # --------------------------------------------------------
            
            ax.set_title(f"Top 10 CWEs: {project_name}", fontsize=14, fontweight='bold')
            ax.set_xlabel("Occurrences")
            ax.set_ylabel("")
        else:
            ax.text(0.5, 0.5, "No Data / No CWEs Mapped", 
                    horizontalalignment='center', verticalalignment='center', 
                    transform=ax.transAxes, color="gray")
            ax.set_title(f"Top 10 CWEs: {project_name}", fontsize=14, fontweight='bold')
            
            # Keep visual consistency even on empty plots
            ax.set_xlim(0, x_limit)

        # Save color reference for the global legend
        handles.append(plt.Rectangle((0,0), 1, 1, color=color, label=project_name))

    # Hide empty subplots (if the grid is larger than the number of projects)
    for j in range(i + 1, len(axes)):
        fig.delaxes(axes[j])

    # Add global legend and title
    fig.legend(handles=handles, title="Projects", loc="upper right", bbox_to_anchor=(0.98, 0.98))
    plt.suptitle("Top 10 CWE's per project", fontsize=18, y=1.02)
    
    plt.tight_layout()
    
    # Save and show the graphic
    output_path = "data/data analysis/top_10_comparison.png"
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    plt.savefig(output_path, bbox_inches='tight')
    print(f"Graphic saved to: {output_path}")
    plt.show()

    
def main():
    #read_and_filter_csv(file_path, output_file_cwe_filter, 10)
    #mapping = get_cwe_mapping()
    #count_per_category(output_file_cwe_filter, output_file_category_count, mapping)
    
    files = [
        "data/datasets/cves_full_argo_cd.csv",
        "data/datasets/cves_full_azure_devops.csv",
        "data/datasets/cves_full_bamboo.csv",
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
        "github",
        "gitlab",
        "jenkins",
        "teamcity",
        "tekton",
        "travis_ci"
    ]
    
    generate_top_10_chart_from_files(files, projects)

if __name__ == "__main__":
    main()