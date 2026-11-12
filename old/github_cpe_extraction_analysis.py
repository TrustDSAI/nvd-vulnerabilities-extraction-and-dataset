import pandas as pd
import json
import ast

# 1. Carregar o dataset
df = pd.read_csv('github.csv')

# =====================================================================
# FUNÇÃO 1: Extração de CPEs Completos (Versões Individuais)
# =====================================================================
def extrair_cpes_completos(config_string):
    if pd.isna(config_string) or config_string in ['[]', '']: return []
    try:
        try: dados = json.loads(config_string)
        except json.JSONDecodeError: dados = ast.literal_eval(config_string)
            
        cpes = []
        def procurar_cpe(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k in ['criteria', 'cpe23Uri']: cpes.append(v)
                    else: procurar_cpe(v)
            elif isinstance(obj, list):
                for item in obj: procurar_cpe(item)
                    
        procurar_cpe(dados)
        return cpes
    except Exception: return []

# =====================================================================
# FUNÇÃO 2: Extração de Produto Base Único por CVE (Vendor:Product)
# =====================================================================
def extrair_produto_base(config_string):
    if pd.isna(config_string) or config_string in ['[]', '']: return []
    try:
        try: dados = json.loads(config_string)
        except json.JSONDecodeError: dados = ast.literal_eval(config_string)
            
        produtos_unicos = set()
        def procurar_cpe(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k in ['criteria', 'cpe23Uri']:
                        partes = v.split(':')
                        if len(partes) >= 5:
                            produtos_unicos.add(f"{partes[3]}:{partes[4]}")
                    else: procurar_cpe(v)
            elif isinstance(obj, list):
                for item in obj: procurar_cpe(item)
                    
        procurar_cpe(dados)
        return list(produtos_unicos)
    except Exception: return []

# =====================================================================
# PROCESSAMENTO DOS DADOS
# =====================================================================
print("A processar os dados...")

df['cpes_completos'] = df['configurations'].apply(extrair_cpes_completos)
df['produtos_base'] = df['configurations'].apply(extrair_produto_base)

# --- GERAR TABELA 1: TODOS OS CPEs (Versões) ---
df_cpes = df.explode('cpes_completos').dropna(subset=['cpes_completos'])
tabela1 = df_cpes['cpes_completos'].value_counts().reset_index()
tabela1.columns = ['CPE Completo (Versão)', 'Frequência (Ocorrências)']

# --- GERAR TABELA 2: TODOS OS PRODUTOS (CVEs Únicas) ---
df_produtos = df.explode('produtos_base').dropna(subset=['produtos_base'])
tabela2 = df_produtos.groupby('produtos_base')['id'].nunique().reset_index()
tabela2.columns = ['Produto Base (Vendor:Product)', 'Total de CVEs Únicas']
tabela2 = tabela2.sort_values(by='Total de CVEs Únicas', ascending=False)

# --- GERAR TABELA 3: APENAS PRODUTOS OFICIAIS DO GITHUB ---
# Filtramos a Tabela 2 para manter apenas os produtos onde o vendor é 'github'
tabela3 = tabela2[tabela2['Produto Base (Vendor:Product)'].str.startswith('github:', na=False)]

# =====================================================================
# RESULTADOS E EXPORTAÇÃO
# =====================================================================
print("\n" + "="*70)
print(f" TABELA 1: TODAS AS VERSÕES ({len(tabela1)} registos)")
print("="*70)
print(tabela1.head(5).to_string(index=False) + "\n... (Ver CSV para lista completa)")

print("\n" + "="*70)
print(f" TABELA 2: TODOS OS PRODUTOS ({len(tabela2)} registos)")
print("="*70)
print(tabela2.head(5).to_string(index=False) + "\n... (Ver CSV para lista completa)")

print("\n" + "="*70)
print(f" TABELA 3: APENAS PRODUTOS GITHUB ({len(tabela3)} registos)")
print("="*70)
print(tabela3.to_string(index=False)) # Imprime a Tabela 3 completa no terminal

# Exportar os resultados completos
tabela1.to_csv('tabela_todas_versoes.csv', index=False, encoding='utf-8')
tabela2.to_csv('tabela_todos_produtos.csv', index=False, encoding='utf-8')
tabela3.to_csv('tabela_apenas_github.csv', index=False, encoding='utf-8')

print("\nFicheiros CSV criados com sucesso!")