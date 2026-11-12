import os
from pathlib import Path

import pandas as pd

# ── Constantes ─────────────────────────────────────────────────────────────────
OLD_DATASET = "data/datasets/cves_merged.csv"          # dataset antigo
NEW_DATASET = "data/new_datasets/dataset_cve.csv"      # dataset novo
DELTA_DIR = "data/new_datasets/"

DIFF_CSV = f"{DELTA_DIR}/delta_diff.csv"               # linhas com + / - na 1.ª coluna
NEW_ONLY_CSV = f"{DELTA_DIR}/delta_new_cves.csv"       # só os CVEs novos, linha completa

ID_COL = "id"
# Se True, CVEs que existem nos dois mas com 'lastModified' diferente aparecem
# no diff como um par (- versão antiga, + versão nova). Não entram no delta de novos.
INCLUDE_MODIFIED = False


def find_project_root() -> Path:
    """Sobe pelas pastas-pai até encontrar a raiz do projeto (a que tem data/new_datasets)."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "data" / "new_datasets").is_dir():
            return parent
    raise FileNotFoundError("Não encontrei a raiz do projeto (pasta com data/new_datasets).")


def load_raw(path: str) -> pd.DataFrame:
    """Lê o CSV como texto, sem converter nada, para as linhas saírem tal como estão."""
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    return df.drop_duplicates(subset=[ID_COL], keep="first").reset_index(drop=True)


def main() -> None:
    os.chdir(find_project_root())

    old = load_raw(OLD_DATASET)
    new = load_raw(NEW_DATASET)
    print(f"Antigo: {len(old)} CVEs ({OLD_DATASET})")
    print(f"Novo:   {len(new)} CVEs ({NEW_DATASET})")

    old_ids, new_ids = set(old[ID_COL]), set(new[ID_COL])

    added = new[~new[ID_COL].isin(old_ids)].sort_values(ID_COL)      # só no novo
    removed = old[~old[ID_COL].isin(new_ids)].sort_values(ID_COL)    # só no antigo

    # ── Delta 1: diff com + / - ───────────────────────────────────────────────
    parts = []

    removed_rows = removed.copy()
    removed_rows.insert(0, "change", "-")
    parts.append(removed_rows)

    if INCLUDE_MODIFIED and "lastModified" in old.columns and "lastModified" in new.columns:
        both = old.merge(new[[ID_COL, "lastModified"]], on=ID_COL, suffixes=("", "_new"))
        changed_ids = set(both.loc[both["lastModified"] != both["lastModified_new"], ID_COL])
        old_changed = old[old[ID_COL].isin(changed_ids)].copy()
        new_changed = new[new[ID_COL].isin(changed_ids)].copy()
        old_changed.insert(0, "change", "-")
        new_changed.insert(0, "change", "+")
        parts += [old_changed, new_changed]
        print(f"CVEs modificados (lastModified diferente): {len(changed_ids)}")

    added_rows = added.copy()
    added_rows.insert(0, "change", "+")
    parts.append(added_rows)

    diff = pd.concat(parts, ignore_index=True).fillna("")
    diff = diff.sort_values([ID_COL, "change"], kind="stable").reset_index(drop=True)

    # ── Escrever ficheiros ────────────────────────────────────────────────────
    os.makedirs(DELTA_DIR, exist_ok=True)
    diff.to_csv(DIFF_CSV, index=False, encoding="utf-8")
    added.to_csv(NEW_ONLY_CSV, index=False, encoding="utf-8")   # mesmo formato do dataset novo

    print(f"\n+ adicionados: {len(added)}")
    print(f"- removidos:   {len(removed)}")
    print(f"\nDiff (+/-):      {DIFF_CSV} ({len(diff)} linhas)")
    print(f"Só CVEs novos:   {NEW_ONLY_CSV} ({len(added)} linhas)")

    if "project" in added.columns and len(added):
        print("\nNovos por projeto:")
        print(added["project"].value_counts().to_string())


if __name__ == "__main__":
    main()