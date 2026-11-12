import pandas as pd

def comparar_datasets_cve(ficheiro1, ficheiro2):
    print(f"A carregar os ficheiros: '{ficheiro1}' e '{ficheiro2}'...\n")
    
    try:
        df1 = pd.read_csv(ficheiro1)
        df2 = pd.read_csv(ficheiro2)
    except FileNotFoundError as e:
        print(f"Erro: Ficheiro não encontrado. Detalhe: {e}")
        return

    # 1. Quantidade Total de CVEs Únicos
    cves_df1 = set(df1['id'].dropna().unique())
    cves_df2 = set(df2['id'].dropna().unique())
    
    print("--- 1. Quantidade Total de CVEs Únicos ---")
    print(f"{ficheiro1}: {len(cves_df1)} CVEs únicos")
    print(f"{ficheiro2}: {len(cves_df2)} CVEs únicos\n")

    # 2. Sobreposição e Exclusividade
    in_both = cves_df1.intersection(cves_df2)
    only_in_df1 = cves_df1 - cves_df2
    only_in_df2 = cves_df2 - cves_df1
    
    print("--- 2. Sobreposição e Exclusividade ---")
    print(f"Presentes em ambos: {len(in_both)} CVEs")
    print(f"Apenas no {ficheiro1}: {len(only_in_df1)} CVEs")
    if len(only_in_df1) > 0:
        print(f"  Exemplos: {list(only_in_df1)[:2]}")
    print(f"Apenas no {ficheiro2}: {len(only_in_df2)} CVEs")
    if len(only_in_df2) > 0:
        print(f"  Exemplos: {list(only_in_df2)[:2]}\n")

    # 3. Estrutura de Dados (Colunas)
    cols_df1 = set(df1.columns)
    cols_df2 = set(df2.columns)
    
    print("--- 3. Estrutura de Dados (Colunas) ---")
    print(f"Colunas apenas em {ficheiro2}: {cols_df2 - cols_df1}")
    print(f"Colunas apenas em {ficheiro1}: {cols_df1 - cols_df2}\n")

    # 4. Duplicação de Registos (Linhas vs Únicos)
    print("--- 4. Duplicação de Registos ---")
    print(f"{ficheiro1}: {len(df1)} linhas no total.")
    print(f"{ficheiro2}: {len(df2)} linhas no total.")
    
    # Identificar os CVEs duplicados e os respetivos projetos
    duplicados_df2 = df2[df2.duplicated(subset=['id'], keep=False)]
    if not duplicados_df2.empty:
        print(f"\nCVEs com múltiplas entradas em {ficheiro2} e os respetivos projetos:")
        print(duplicados_df2[['id', 'project']].sort_values(by='id').to_string(index=False))

# Executar a função
comparar_datasets_cve('data/datasets/cves_merged.csv', 'data/new_datasets/dataset_cve.csv')