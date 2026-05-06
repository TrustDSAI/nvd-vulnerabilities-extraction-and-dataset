import csv
from collections import defaultdict

# Path to cwe csv file
file_path = "cwe_counts.csv"
output_file = "cwe_summary.csv"

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
    if cnt >= 10:
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