import pandas as pd
import re
from collections import Counter

input_file = 'data/datasets/cves_merged.csv'
print(f"Loading data from {input_file}...")
df = pd.read_csv(input_file)

# Combine all descriptions into a single massive string
# Using fillna('') ensures we don't get errors if a row has missing data
all_descriptions = " ".join(df.get('descriptions', '').fillna('').astype(str).tolist())

# Extract words with 3 or more letters (converted to lowercase)
words = re.findall(r'\b[a-z]{3,}\b', all_descriptions.lower())

# Highly improved and categorized stop_words list to filter out noise
stop_words = {
    # 1. JSON Structure and Formatting
    'lang', 'value', 'description', 'source', 'type', 'primary', 'cve', 
    
    # 2. English - Common and Connecting Words
    'the', 'and', 'for', 'that', 'this', 'with', 'from', 'which', 'when', 'not', 'all', 
    'was', 'has', 'been', 'have', 'are', 'through',
    
    # 3. Spanish - Common and Connecting Words
    'que', 'las', 'una', 'todas', 'los', 'del', 'para', 'hasta', 'con', 'por', 'esta',
    'desde', 'partir', 'tipo', 'era', 'puede', 'cuando',
    
    # 4. Generic CVE and Security Jargon (English)
    'vulnerability', 'issue', 'allows', 'attacker', 'attackers', 'arbitrary', 'could', 'via',
    'user', 'users', 'versions', 'version', 'before', 'after', 'execution', 'code', 'access',
    'remote', 'authenticated', 'information', 'discovered', 'affecting', 'prior', 'starting',
    'allowed', 'possible', 'earlier', 'vulnerable', 'bug', 'fixed', 'crafted', 'affected',
    
    # 5. Generic CVE and Security Jargon (Spanish)
    'versiones', 'anteriores', 'problema', 'vulnerabilidad', 'anterior', 'permite', 'afecta', 
    'acceso', 'atacante', 'atacantes', 'antes', 'usuario', 'usuarios', 'posible', 'descubierto',
    'permisos',
    
    # 6. Editions, Projects, and Platform "Noise"
    'enterprise', 'server', 'edition', 'community', 'lts', 'project', 'proyecto', 'service', 
    'servicio', 'bounty', 'jetbrains', 'gitlab', 'github', 'jenkins', 'teamcity', 'argo'
}

# Filter the list keeping only meaningful words
meaningful_words = [word for word in words if word not in stop_words]

# Count the frequencies
word_counts = Counter(meaningful_words)

# Print the new Top 100 focusing only on pure technical terms
print("\nTop 100 Technical Words:")
for word, count in word_counts.most_common(100):
    print(f"{word}: {count}")