import os
import glob
import re

# 1. Configurações
diretorio = '../data/datasets'             
extensao = '*.csv'           
ficheiro_apenas_cpes = '1_lista_cpes_unicos.txt'
ficheiro_cpes_com_origem = '2_cpes_por_ficheiro_e_cve.txt'
ficheiro_cpes_base = '3_cpes_sem_versao.txt' 

# NOVA CONFIGURAÇÃO: Lista de ficheiros a ignorar (coloca o nome exato com a extensão)
ficheiros_a_ignorar = ["cves_merged.csv", "cves_processed_full.csv"]  # Adicione os nomes dos ficheiros que deseja ignorar

# 2. Expressões Regulares
padrao_cpe = re.compile(r'cpe:[a-zA-Z0-9\.\_\-\~\%\:\/\*]+')
padrao_cve = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

# Sets para guardar a informação
cpes_unicos = set()
cpes_mapeados = set() 
cpes_base_unicos = set()

# Função para extrair apenas a base do CPE
def extrair_base_cpe(cpe):
    partes = cpe.split(':')
    try:
        if cpe.startswith('cpe:2.3:'):
            return ':'.join(partes[:5]) + ':'
        else:
            return ':'.join(partes[:4]) + ':'
    except:
        return cpe 

# 3. Percorrer os ficheiros
caminho_busca = os.path.join(diretorio, extensao)
for caminho_ficheiro in glob.glob(caminho_busca):
    nome_ficheiro = os.path.basename(caminho_ficheiro)
    
    # VALIDAÇÃO: Se o ficheiro estiver na lista de exclusão, salta para o próximo
    if nome_ficheiro in ficheiros_a_ignorar:
        print(f"-> A ignorar o ficheiro: {nome_ficheiro}")
        continue

    try:
        with open(caminho_ficheiro, 'r', encoding='utf-8') as f:
            for linha in f:
                cpes_na_linha = padrao_cpe.findall(linha)
                
                if not cpes_na_linha:
                    continue
                
                cves_na_linha = padrao_cve.findall(linha)
                cve_associado = cves_na_linha[0].upper() if cves_na_linha else "CVE-Desconhecido"
                
                for cpe in cpes_na_linha:
                    cpes_unicos.add(cpe)
                    cpes_mapeados.add((nome_ficheiro, cve_associado, cpe))
                    cpes_base_unicos.add(extrair_base_cpe(cpe))
                    
    except Exception as e:
        print(f"Erro ao ler {nome_ficheiro}: {e}")

# 4. Gravar Ficheiro 1: Apenas CPEs
if cpes_unicos:
    with open(ficheiro_apenas_cpes, 'w', encoding='utf-8') as f1:
        for cpe in sorted(cpes_unicos):
            f1.write(cpe + '\n')
    print(f"-> Criado: '{ficheiro_apenas_cpes}' ({len(cpes_unicos)} CPEs globais)")

# 5. Gravar Ficheiro 2: CPEs por Ficheiro e CVE
if cpes_mapeados:
    with open(ficheiro_cpes_com_origem, 'w', encoding='utf-8') as f2:
        for nome_ficheiro, cve, cpe in sorted(cpes_mapeados):
            f2.write(f"[{nome_ficheiro}] | {cve}  -->  {cpe}\n")
    print(f"-> Criado: '{ficheiro_cpes_com_origem}' (Agrupado por ficheiro e CVE)")

# 6. Gravar Ficheiro 3: CPEs base (Sem versão)
if cpes_base_unicos:
    with open(ficheiro_cpes_base, 'w', encoding='utf-8') as f3:
        for base_cpe in sorted(cpes_base_unicos):
            f3.write(base_cpe + '\n')
    print(f"-> Criado: '{ficheiro_cpes_base}' ({len(cpes_base_unicos)} CPEs base únicos)")