import csv
from collections import defaultdict
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
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

def calculate_global_cwe_counts_with_report(input_csv_path, output_csv_path):
    print(f"\n--- Calculating global CWE totals and reporting low-frequency items ---")
    
    cwe_totals = defaultdict(int)
    exclude_noise = ["NVD-CWE-noinfo", "NVD-CWE-Other"]
    
    # 1. Read the CSV and aggregate
    try:
        with open(input_csv_path, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row['project'] == 'Total':
                    continue
                
                cwe = row['cwes']
                count = int(row['count'])
                cwe_totals[cwe] += count
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # 2. Separate into ">= 10" and "< 10" (excluding noise)
    high_freq = {}
    less_than_10_count = 0
    less_than_10_names = []

    for cwe, total in cwe_totals.items():
        if total >= 10:
            high_freq[cwe] = total
        elif cwe not in exclude_noise:
            less_than_10_count += total
            less_than_10_names.append(cwe)

    # 3. Print the requested report
    print(f"\n--- Statistics for CWEs with < 10 occurrences ---")
    print(f"Total occurrences (excluding noise): {less_than_10_count}")
    print(f"Number of distinct CWE types found with < 10 occurrences: {len(less_than_10_names)}")
    print(f"Types found: {', '.join(less_than_10_names)}")

    # 4. Save ALL results to CSV
    sorted_all = sorted(cwe_totals.items(), key=lambda x: x[1], reverse=True)

    try:
        os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
        with open(output_csv_path, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['cwe', 'total_count'])
            writer.writerows(sorted_all)
            total_sum = sum(cwe_totals.values())
            writer.writerow(['Total', total_sum])

        print(f"\nSuccess! Full CWE totals saved to: {output_csv_path}")
    except Exception as e:
        print(f"Error saving file: {e}")
        
def count_cves_per_category_and_export_conflicts(files_list, projects_list, output_conflicts_csv, output_summary_csv):
    """
    Counts unique CVEs per category ONLY for CVEs with CWEs from a single category.
    
    Rules:
    1. Pure CVE: All CWEs mapped and belong to the SAME category -> counts for that category
    2. Conflict CVE: All CWEs mapped but belong to DIFFERENT categories -> goes to conflicts CSV
    3. Unmapped CVE: At least one CWE not in mapping -> goes to unmapped CSV (does NOT count for any category)
    4. Excluded-only CVE: Only NVD-CWE-noinfo and/or NVD-CWE-Other -> goes to excluded CSV
    
    Args:
        files_list: List of paths to CSV files containing CVE data
        projects_list: List of project names corresponding to each file
        output_conflicts_csv: Path where conflicts CSV will be saved
        output_summary_csv: Path where category summary CSV will be saved
    
    Returns:
        tuple: (category_cves dict, conflict_cves list, unmapped_cves list, excluded_only_cves list)
    """
    
    # Get CWE to category mapping
    mapping = get_cwe_mapping()
    
    # CWEs to exclude from analysis (treated separately)
    exclude_cwes = ["NVD-CWE-Other", "NVD-CWE-noinfo"]
    
    # Dictionary to count CVEs per category (only "pure" CVEs - Case 1)
    category_cves = defaultdict(list)
    
    # Lists for different CVE categories
    conflict_cves = []      # Case 2: mapped but different categories
    unmapped_cves = []      # Case 3: at least one unmapped CWE
    excluded_only_cves = [] # Case 4: only excluded CWEs
    
    # Statistics counters
    total_cves_processed = 0
    total_pure_cves = 0
    total_conflict_cves = 0
    total_unmapped_cves = 0
    total_excluded_only_cves = 0
    
    # Counters for unmapped and excluded CWE occurrences
    unmapped_cwe_count = 0
    unmapped_cwe_set = set()
    noinfo_count = 0
    other_count = 0
    
    # Process each project's data
    for file_path, project_name in zip(files_list, projects_list):
        try:
            df = load_cve_dataset(file_path)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            continue
        
        # Extract list of CWEs for each CVE
        df["cwes"] = df["weaknesses"].apply(extract_cwes_list)
        
        # Identify the CVE ID column name
        id_col = next((col for col in ["cveId", "id", "cve_id", "CVE_ID"] if col in df.columns), None)
        
        if not id_col:
            print(f"Warning: No CVE ID column found in {project_name}")
            continue
        
        # Iterate through each CVE in the dataset
        for _, row in df.iterrows():
            cve_id = str(row[id_col]) if pd.notna(row[id_col]) else None
            if not cve_id:
                continue
            
            cwe_list = row["cwes"]
            
            total_cves_processed += 1
            
            # Count NVD-CWE-noinfo and NVD-CWE-Other occurrences
            for cwe in cwe_list:
                if cwe == "NVD-CWE-noinfo":
                    noinfo_count += 1
                elif cwe == "NVD-CWE-Other":
                    other_count += 1
            
            # Classify each CWE
            has_excluded_only = True
            has_mapped_cwe = False
            has_unmapped_cwe = False
            categories_for_cve = set()
            unmapped_cwes_in_cve = []
            mapped_cwes_in_cve = []
            excluded_cwes_in_cve = []
            
            for cwe in cwe_list:
                if cwe in exclude_cwes:
                    excluded_cwes_in_cve.append(cwe)
                    continue  # Skip excluded CWEs for category analysis
                
                has_excluded_only = False  # Found a non-excluded CWE
                
                # Get category for this CWE
                category = get_cwe_category(cwe, mapping)
                
                if category == "Unmapped":
                    has_unmapped_cwe = True
                    unmapped_cwes_in_cve.append(cwe)
                    unmapped_cwe_count += 1
                    unmapped_cwe_set.add(cwe)
                elif category != "Invalid format!":
                    has_mapped_cwe = True
                    mapped_cwes_in_cve.append(cwe)
                    categories_for_cve.add(category)
                # Invalid format is ignored (should not happen with valid data)
            
            # CASE 4: Only excluded CWEs (NVD-CWE-noinfo / NVD-CWE-Other)
            if has_excluded_only and not has_mapped_cwe and not has_unmapped_cwe:
                total_excluded_only_cves += 1
                excluded_only_cves.append({
                    "project": project_name,
                    "cve_id": cve_id,
                    "cwes": ", ".join(cwe_list) if cwe_list else "No CWEs"
                })
                continue
            
            # CASE 3: At least one unmapped CWE (regardless of mapped ones)
            if has_unmapped_cwe:
                total_unmapped_cves += 1
                cwes_str = ", ".join(cwe_list)
                mapped_str = ", ".join(mapped_cwes_in_cve) if mapped_cwes_in_cve else "None"
                unmapped_str = ", ".join(unmapped_cwes_in_cve)
                categories_str = ", ".join(sorted(categories_for_cve)) if categories_for_cve else "None"
                
                unmapped_cves.append({
                    "project": project_name,
                    "cve_id": cve_id,
                    "all_cwes": cwes_str,
                    "mapped_cwes": mapped_str,
                    "unmapped_cwes": unmapped_str,
                    "categories_found": categories_str
                })
                continue
            
            # CASE 1 & 2: All CWEs are mapped (no unmapped, no excluded-only)
            if has_mapped_cwe:
                if len(categories_for_cve) == 1:
                    # CASE 1: Pure CVE - single category
                    total_pure_cves += 1
                    category = next(iter(categories_for_cve))
                    category_cves[category].append(cve_id)
                else:
                    # CASE 2: Conflict CVE - multiple categories
                    total_conflict_cves += 1
                    cwes_str = ", ".join(mapped_cwes_in_cve)
                    categories_str = ", ".join(sorted(categories_for_cve))
                    
                    conflict_cves.append({
                        "project": project_name,
                        "cve_id": cve_id,
                        "cwes": cwes_str,
                        "categories": categories_str,
                        "num_categories": len(categories_for_cve)
                    })
    
    # Print statistics to console
    print(f"\n{'='*70}")
    print(f"CATEGORY COUNTING STATISTICS (By CVE Classification)")
    print(f"{'='*70}")
    
    print(f"\n--- CVE Processing Summary ---")
    print(f"Total CVEs processed: {total_cves_processed}")
    print(f"\n  CASE 1 - Pure CVEs (mapped, single category): {total_pure_cves}")
    print(f"  CASE 2 - Conflict CVEs (mapped, multiple categories): {total_conflict_cves}")
    print(f"  CASE 3 - Unmapped CVEs (at least one unmapped CWE): {total_unmapped_cves}")
    print(f"  CASE 4 - Excluded-only CVEs (only NVD-CWE-noinfo/Other): {total_excluded_only_cves}")
    
    # Verification
    calculated_total = total_pure_cves + total_conflict_cves + total_unmapped_cves + total_excluded_only_cves
    if calculated_total != total_cves_processed:
        print(f"\n⚠️ WARNING: Sum mismatch! {calculated_total} vs {total_cves_processed}")
    else:
        print(f"\n✓ Sum verification: {calculated_total} = {total_cves_processed}")
    
    if total_cves_processed > 0:
        print(f"\n--- Percentages ---")
        print(f"  Pure CVEs: {total_pure_cves/total_cves_processed*100:.2f}%")
        print(f"  Conflict CVEs: {total_conflict_cves/total_cves_processed*100:.2f}%")
        print(f"  Unmapped CVEs: {total_unmapped_cves/total_cves_processed*100:.2f}%")
        print(f"  Excluded-only CVEs: {total_excluded_only_cves/total_cves_processed*100:.2f}%")
    
    # Print unmapped CWE statistics
    print(f"\n--- Unmapped CWE Statistics ---")
    print(f"Unmapped CWE occurrences: {unmapped_cwe_count}")
    print(f"Unique unmapped CWE types: {len(unmapped_cwe_set)}")
    if unmapped_cwe_set:
        print(f"Unmapped CWE types: {', '.join(sorted(unmapped_cwe_set))}")
    
    # Print excluded CWE statistics
    print(f"\n--- Excluded CWE Statistics ---")
    print(f"NVD-CWE-noinfo occurrences: {noinfo_count}")
    print(f"NVD-CWE-Other occurrences: {other_count}")
    print(f"Total excluded occurrences: {noinfo_count + other_count}")
    
    # Export all CSV files
    os.makedirs(os.path.dirname(output_conflicts_csv), exist_ok=True)
    
    # 1. Export conflicts CSV (Case 2)
    if conflict_cves:
        conflicts_path = output_conflicts_csv
        with open(conflicts_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["project", "cve_id", "cwes", "categories", "num_categories"])
            writer.writeheader()
            writer.writerows(conflict_cves)
        print(f"\n--- File Output ---")
        print(f"Conflicts file (Case 2): {conflicts_path}")
        print(f"  Total conflicts: {len(conflict_cves)}")
    
    # 2. Export unmapped CVEs CSV (Case 3)
    if unmapped_cves:
        unmapped_path = output_conflicts_csv.replace(".csv", "_unmapped_cves.csv")
        with open(unmapped_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["project", "cve_id", "all_cwes", "mapped_cwes", "unmapped_cwes", "categories_found"])
            writer.writeheader()
            writer.writerows(unmapped_cves)
        print(f"Unmapped CVEs file (Case 3): {unmapped_path}")
        print(f"  Total unmapped CVEs: {len(unmapped_cves)}")
    
    # 3. Export excluded-only CVEs CSV (Case 4)
    if excluded_only_cves:
        excluded_path = output_conflicts_csv.replace(".csv", "_excluded_only.csv")
        with open(excluded_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["project", "cve_id", "cwes"])
            writer.writeheader()
            writer.writerows(excluded_only_cves)
        print(f"Excluded-only CVEs file (Case 4): {excluded_path}")
        print(f"  Total excluded-only CVEs: {len(excluded_only_cves)}")
    
    # 4. Export category summary (Case 1 only)
    export_category_summary(category_cves, output_summary_csv, total_pure_cves)
    
    return category_cves, conflict_cves, unmapped_cves, excluded_only_cves


def export_category_summary(category_cves, output_csv_path, total_cves):
    """
    Exports the summary of CVEs per category to a CSV file.
    Includes the total count of pure CVEs at the bottom.
    
    Args:
        category_cves: Dictionary mapping category names to sets of CVE IDs
        output_csv_path: Path where the summary CSV will be saved
        total_cves: Total number of pure CVEs (for percentage calculation)
    """
    
    # Sort categories by number of CVEs (descending)
    sorted_categories = sorted(category_cves.items(), key=lambda x: len(x[1]), reverse=True)
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
    
    # Write to CSV file
    with open(output_csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Write header
        writer.writerow(['Category', 'unique_cves', 'percentage'])
        
        # Write data for each category
        for category, cve_set in sorted_categories:
            count = len(cve_set)
            percentage = (count / total_cves * 100) if total_cves > 0 else 0
            writer.writerow([category, count, f"{percentage:.2f}%"])
        
        # Write total row
        writer.writerow(['TOTAL', total_cves, '100%'])
    
    print(f"\nCategory summary saved to: {output_csv_path}")
    print(f"Total pure CVEs (Case 1): {total_cves}")
    
    # Also print summary to console
    if total_cves > 0:
        print(f"\n--- Category Summary (Pure CVEs Only - Case 1) ---")
        for category, cve_set in sorted_categories:
            count = len(cve_set)
            percentage = (count / total_cves * 100) if total_cves > 0 else 0
            print(f"  {category}: {count} CVEs ({percentage:.2f}%)")

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
    excluded = ["tekton", "travis_ci", "bamboo", "bitbucket"]
    for file_path, project_name in zip(files_list, projects_list):
        if project_name not in excluded:
            try:
                # Assuming load_cve_dataset is defined elsewhere
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
    # Assuming extract_cwes_list is defined elsewhere
    df["cwes"] = df["weaknesses"].apply(extract_cwes_list)
    exploded = df.explode("cwes")

    # Noise removal
    exclude = ["NVD-CWE-noinfo", "NVD-CWE-Other"]
    clean_df = exploded[~exploded["cwes"].isin(exclude)].copy()

    # Find global maximum count to standardize the X-axis
    max_x_count = 0
    for project_name in projects_list:
        if project_name not in excluded:
            proj_counts = clean_df[clean_df["project"] == project_name]["cwes"].value_counts().head(10)
            if not proj_counts.empty:
                max_x_count = max(max_x_count, proj_counts.max())

    # Add a 5% padding so the largest bar doesn't touch the edge of the plot
    x_limit = max_x_count * 1.05

    # 2. Configure the subplot grid
    # Safely count only the included projects
    num_projects = len([p for p in projects_list if p not in excluded]) 
    cols = 3
    rows = (num_projects + cols - 1) // cols

    sns.set_theme(style="whitegrid")
    fig, axes = plt.subplots(rows, cols, figsize=(18, 5 * rows))
    axes = axes.flatten()

    palette = sns.color_palette("tab10", n_colors=num_projects)
    handles = []
    plot_idx = 0
    
    # 3. Iterate over each project and plot its bar chart
    for project_name in projects_list:
        if project_name not in excluded:
            ax = axes[plot_idx]
            color = palette[plot_idx]

            proj_data = clean_df[clean_df["project"] == project_name]
            cwe_counts = proj_data["cwes"].value_counts()
            top_cwes = cwe_counts.head(10).reset_index()
            top_cwes.columns = ["cwe", "count"]

            if not top_cwes.empty:
                # Compute "Others" as the sum of all CWEs outside the top 10
                others_count = cwe_counts.iloc[10:].sum()
                if others_count > 0:
                    others_row = pd.DataFrame([{"cwe": "Others", "count": others_count}])
                    top_cwes = pd.concat([top_cwes, others_row], ignore_index=True)

                # Use a distinct color for the "Others" bar
                bar_colors = [color] * (len(top_cwes) - 1) + ["lightgray"]

                sns.barplot(data=top_cwes, x="count", y="cwe", ax=ax, palette=bar_colors)

                # Manual control of number placement
                for p in ax.patches:
                    width = p.get_width()
                    
                    if width == 0 or pd.isna(width):
                        continue 
                    
                    if width >= x_limit * 0.8:
                        text_x = x_limit * 0.95 
                        alignment = 'right'    
                        text_color = 'black'     
                    else:
                        text_x = width + (x_limit * 0.02)
                        alignment = 'left'
                        text_color = 'black'
                    
                    y_pos = p.get_y() + (p.get_height() / 2) + p.get_height() * 0.1
                    
                    ax.text(
                        x=text_x, 
                        y=y_pos, 
                        s=f'{int(width)}', 
                        ha=alignment, 
                        va='center', 
                        fontsize=10, 
                        color=text_color,
                        fontweight='bold'
                    )

            else:
                ax.text(0.5, 0.5, "No Data / No CWEs Mapped",
                        horizontalalignment="center", verticalalignment="center",
                        transform=ax.transAxes, color="gray")

            # Apply limits and titles
            ax.set_xlim(0, x_limit)
            ax.set_title(f"Top 10 CWEs: {project_name}", fontsize=14, fontweight="bold")
            ax.set_xlabel("Occurrences")
            ax.set_ylabel("")
            
            handles.append(plt.Rectangle((0, 0), 1, 1, color=color, label=project_name))
            plot_idx += 1

    # Hide any remaining empty subplots using the actual plot count
    for j in range(plot_idx, len(axes)):
        fig.delaxes(axes[j])

    # Add "Others" to the global legend
    handles.append(plt.Rectangle((0, 0), 1, 1, color="lightgray", label="Others"))

    fig.legend(handles=handles, title="Projects", loc="upper right", bbox_to_anchor=(1.1, 0.62))

    plt.tight_layout()

    output_path = "data/data analysis/top_10_comparison.pdf"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.savefig(output_path, bbox_inches="tight")
    print(f"Graphic saved to: {output_path}")
    plt.show()

##################
# Stacked Area Charts and Heatmaps
##################

def _save(fig: plt.Figure, filename: str, output_dir: str = "data/data analysis") -> None:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    fig.savefig(path, bbox_inches="tight")
    print(f"Saved: {path}")
    plt.show()

def plot_heatmap_year_category(df: pd.DataFrame) -> None:
    pivot = (df.groupby(["year", "category"]).size().unstack(fill_value=0).sort_index())
    fig, ax = plt.subplots(figsize=(14, 5))
    sns.heatmap(pivot.T, annot=True, fmt="d", cmap="Blues", linewidths=0.4, ax=ax)
    ax.set_title("Vulnerabilities per Year × Category", fontsize=14, fontweight="bold")
    ax.set_xlabel("Year")
    ax.set_ylabel("Category")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    _save(fig, "heatmap_year_category.png")

def plot_heatmap_year_project(df: pd.DataFrame) -> None:
    pivot = (df.groupby(["year", "project"]).size().unstack(fill_value=0).sort_index())
    fig, ax = plt.subplots(figsize=(14, 5))
    sns.heatmap(pivot.T, annot=True, fmt="d", cmap="Blues", linewidths=0.4, ax=ax)
    ax.set_title("Vulnerabilities per Year × Project", fontsize=14, fontweight="bold")
    ax.set_xlabel("Year")
    ax.set_ylabel("Project")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    _save(fig, "heatmap_year_project.png")

def plot_heatmap_project_category(df: pd.DataFrame) -> None:
    pivot = (df.groupby(["project", "category"]).size().unstack(fill_value=0))
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

    categorias_agrupar = ["System Configuration", "Output Encoding", "Error Handling", "File Management"]
    novo_nome = "Others"

    df_plot.loc[df_plot["category"].isin(categorias_agrupar), "category"] = novo_nome

    pivot = (df_plot.groupby(["year", "category"]).size().unstack(fill_value=0).sort_index())
    
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

    projetos_agrupar = ["bamboo", "tekton", "travis_ci"]
    novo_nome = "Others"

    df_plot.loc[df_plot["project"].isin(projetos_agrupar), "project"] = novo_nome

    pivot = (df_plot.groupby(["year", "project"]).size().unstack(fill_value=0).sort_index())
    
    fig, ax = plt.subplots(figsize=(14, 6))
    pivot.plot.area(ax=ax, colormap="tab10", alpha=0.85)
    
    ax.set_title("Vulnerability Trends by Project (Stacked Area)", fontsize=14, fontweight="bold")
    ax.set_xlabel("Year")
    ax.set_ylabel("CVE Count")
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.legend(title="Project", bbox_to_anchor=(1.01, 1), loc="upper left")
    
    plt.tight_layout()
    
    _save(fig, "area_project_grouped.pdf")
    
def generate_temporal_and_category_charts(files_list, projects_list):
    mapping = get_cwe_mapping()
    dfs = []
    
    for file_path, project_name in zip(files_list, projects_list):
        try:
            df = load_cve_dataset(file_path)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            continue

        df["project"] = project_name
        
        # Obter o ano da coluna 'published'
        if "published" in df.columns:
            df["year"] = pd.to_datetime(df["published"], errors="coerce").dt.year
        else:
            df["year"] = None
            
        df["cwes"] = df["weaknesses"].apply(extract_cwes_list)
        exploded = df.explode("cwes").dropna(subset=["cwes"])

        exclude = ["NVD-CWE-noinfo", "NVD-CWE-Other", "Invalid format!"]
        exploded = exploded[~exploded["cwes"].isin(exclude)].copy()

        # Mapeamento
        exploded["category"] = exploded["cwes"].apply(lambda x: get_cwe_category(x, mapping))
        exploded = exploded[~exploded["category"].isin(["Invalid format!", "Unmapped"])]

        dfs.append(exploded[["project", "year", "cwes", "category"]])

    if not dfs:
        print("No data loaded for temporal charts.")
        return

    # Juntar os dados todos
    master_df = pd.concat(dfs, ignore_index=True)
    master_df = master_df.dropna(subset=["year"])
    master_df["year"] = master_df["year"].astype(int)

    # Chamar os 5 gráficos
    plot_heatmap_year_category(master_df)
    plot_heatmap_year_project(master_df)
    plot_heatmap_project_category(master_df)
    plot_area_category(master_df)
    plot_area_project(master_df)

def export_cves_with_multiple_categories(files_list, projects_list, output_csv_path):
    print(f"\n--- Exporting CVEs with multiple categories to {output_csv_path} ---")
    mapping = get_cwe_mapping()
    exclude_cwes = ["NVD-CWE-noinfo", "NVD-CWE-Other"]
    
    # List to store the rows that will be written to the CSV
    csv_rows = []

    for file_path, project_name in zip(files_list, projects_list):
        try:
            df = load_cve_dataset(file_path)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            continue

        # 1. Extract the list of CWEs
        df["cwes"] = df["weaknesses"].apply(extract_cwes_list)
        
        # 2. Map unique categories
        def get_unique_categories(cwe_list):
            categories = set()
            for cwe in cwe_list:
                if cwe in exclude_cwes:
                    continue
                cat = get_cwe_category(cwe, mapping)
                if cat not in ["Invalid format!", "Unmapped"]:
                    categories.add(cat)
            return list(categories)

        df["unique_categories"] = df["cwes"].apply(get_unique_categories)
        df["category_count"] = df["unique_categories"].apply(len)

        # 3. Filter CVEs with multiple categories
        multiple_cats_df = df[df["category_count"] > 1]
        
        if not multiple_cats_df.empty:
            # Try to dynamically discover the CVE ID column name
            id_col = next((col for col in ["cveId", "id", "cve_id", "CVE_ID"] if col in df.columns), None)
            
            # 4. Prepare data for the CSV
            for _, row in multiple_cats_df.iterrows():
                # Safely extract the ID
                cve_id = str(row[id_col]) if id_col and pd.notna(row[id_col]) else "Unknown_ID"
                
                # Convert lists to strings (filtering excluded CWEs)
                cwes_str = ", ".join([cwe for cwe in row["cwes"] if cwe not in exclude_cwes])
                cats_str = ", ".join(row["unique_categories"])
                
                # Add the record to the list
                csv_rows.append([project_name, cve_id, cwes_str, cats_str])

    # 5. Write to the CSV file
    try:
        os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
        
        with open(output_csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Write the header
            writer.writerow(["project", "cve_id", "cwes", "categories"])
            writer.writerows(csv_rows)
            
        print(f"Success! {len(csv_rows)} records were saved to the file: {output_csv_path}")
    except Exception as e:
        print(f"Error saving the CSV file: {e}")

def main():
    #read_and_filter_csv(file_path, output_file_cwe_filter, 10)
    #mapping = get_cwe_mapping()
    #count_per_category(output_file_cwe_filter, output_file_category_count, mapping)
    
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
    
    #generate_top_10_chart_from_files(files, projects)

    #generate_temporal_and_category_charts(files, projects)

    cwe_per_project_csv = "data/data analysis/cwe_analysis/cwe_counts.csv"
    cwe_totals_csv = "data/data analysis/cwe_analysis/cwe_total_global.csv"
    
    #calculate_global_cwe_counts_with_report(cwe_per_project_csv, cwe_totals_csv)

    #export_cves_with_multiple_categories(files, projects, "data/data analysis/multiple_categories_cves.csv")
    category_cves, conflict_cves, unmapped_cves, excluded_only_cves = count_cves_per_category_and_export_conflicts(
        files, 
        projects, 
        "data/data analysis/cve_category_conflicts.csv",
        "data/data analysis/cve_category_summary.csv"
    )
if __name__ == "__main__":
    main()