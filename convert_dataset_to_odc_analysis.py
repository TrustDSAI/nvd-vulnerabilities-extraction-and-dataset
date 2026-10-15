import pandas as pd
import json
import os

# ── Configurações ──────────────────────────────────────────────────────────
INPUT_CSV = "data/new_datasets/dataset_cve.csv"
OUTPUT_CSV = "data/new_datasets/dataset_cve_parsed.csv" # Guarda diretamente na pasta antiga

def extrair_cwes(weaknesses_str):
    """Lê o JSON das weaknesses e extrai os códigos CWE."""
    if pd.isna(weaknesses_str) or not weaknesses_str:
        return ""
    try:
        weaknesses = json.loads(weaknesses_str)
        cwes_encontrados = set()
        
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE") or val.startswith("NVD-CWE"):
                    cwes_encontrados.add(val)
                    
        return ", ".join(sorted(cwes_encontrados))
    except Exception:
        return ""

def extrair_cvss(metrics_str):
    """Lê o JSON das metrics e extrai o Score e a Versão do CVSS (prioriza V3.1 > V3.0 > V2.0)."""
    if pd.isna(metrics_str) or not metrics_str:
        return "", ""
    try:
        metrics = json.loads(metrics_str)
        # Procura a versão mais recente disponível
        for versao_cvss in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if versao_cvss in metrics and len(metrics[versao_cvss]) > 0:
                cvss_data = metrics[versao_cvss][0].get("cvssData", {})
                score = cvss_data.get("baseScore", "")
                version = cvss_data.get("version", "")
                return score, version
        return "", ""
    except Exception:
        return "", ""

def main():
    print(f"A ler o ficheiro bruto: {INPUT_CSV}")
    df = pd.read_csv(INPUT_CSV, dtype=str)

    # 1. Extrair o Ano (a partir do ID CVE-YYYY-NNNN)
    df["year"] = df["id"].apply(lambda x: str(x).split("-")[1] if pd.notna(x) and str(x).startswith("CVE-") else "")

    # 2. Criar a coluna project_extracted (cópia da coluna project para compatibilidade)
    if "project" in df.columns:
        df["project_extracted"] = df["project"]
    else:
        df["project_extracted"] = ""

    # 3. Fazer o parse dos CWEs
    print("A extrair CWEs...")
    df["cwes"] = df["weaknesses"].apply(extrair_cwes)

    # 4. Fazer o parse do CVSS
    print("A extrair dados CVSS...")
    cvss_dados = df["metrics"].apply(extrair_cvss)
    df["cvss_score"] = [x[0] for x in cvss_dados]
    df["cvss_version"] = [x[1] for x in cvss_dados]

    # 5. Organizar as colunas exatamente pela mesma ordem do dataset antigo
    colunas_finais = [
        "id", "sourceIdentifier", "published", "lastModified", "vulnStatus", 
        "descriptions", "weaknesses", "configurations", "references", "cveTags", 
        "metrics", "project", "year", "project_extracted", "cwes", "cvss_score", "cvss_version"
    ]

    # Preencher com vazio caso alguma coluna do layout antigo não exista no dataframe atual
    for col in colunas_finais:
        if col not in df.columns:
            df[col] = ""

    # Reordenar dataframe
    df = df[colunas_finais]

    # Guardar no destino
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")
    
    print(f"Sucesso! Dataset limpo guardado em: {OUTPUT_CSV}")

if __name__ == "__main__":
    main()