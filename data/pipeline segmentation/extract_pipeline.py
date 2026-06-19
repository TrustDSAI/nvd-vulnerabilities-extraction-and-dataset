import pandas as pd
import re

# 1. Define pure CI/CD tools
pure_cicd_projects = ['argo cd', 'bamboo', 'jenkins', 'teamcity', 'tekton', 'travis ci']

# 2. Define broad platforms
broad_platforms = ['azure devops', 'bitbucket', 'github', 'gitlab']

# 3. Define the CI/CD concepts
concepts_pattern = r'\b(pipeline|continuous integration|continuous delivery|continuous deployment|actions|workflow|runner|ci/cd|webhook)\b'
regex_concepts = re.compile(concepts_pattern, re.IGNORECASE)

def classify_vulnerability(row):
    """
    Classifies if a vulnerability is related to CI/CD.
    """
    project = str(row.get('project', '')).lower().replace('_', ' ')
    description = str(row.get('descriptions', '')).lower()
    
    if any(pure_tool in project for pure_tool in pure_cicd_projects):
        return "CI/CD (Pure Project)"
        
    if any(platform in project for platform in broad_platforms):
        if bool(regex_concepts.search(description)):
            return "CI/CD (Broad Platform + Keyword Match)"
        else:
            return "Not CI/CD"
            
    return "Not CI/CD"

# ==========================================
# Processing the merged CSV
# ==========================================

input_file = 'data/datasets/cves_merged.csv'
output_file = 'data/pipeline segmentation/cves_only_cicd.csv'

print(f"Loading data from {input_file}...")
df = pd.read_csv(input_file)

# Apply the classification to a temporary column
df['temp_classification'] = df.apply(classify_vulnerability, axis=1)

# Print a summary before filtering
print("\nSummary before filtering:")
print(df['temp_classification'].value_counts().to_string())

# FILTER: Keep only the rows classified as CI/CD
df_filtered = df[df['temp_classification'].isin(['CI/CD (Pure Project)', 'CI/CD (Broad Platform + Keyword Match)'])]

# DROP: Remove the temporary classification column so it is not saved
df_filtered = df_filtered.drop(columns=['temp_classification'])

# Save the file with only the relevant vulnerabilities
df_filtered.to_csv(output_file, index=False)

print(f"\nDone! Cleaned file saved to: {output_file}")
print(f"Total CI/CD vulnerabilities extracted: {len(df_filtered)}")