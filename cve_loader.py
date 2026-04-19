import pandas as pd
import json
import math

def load_cve_dataset(csv_path: str) -> pd.DataFrame:
    """
    Loads CVE dataset and safely parses JSON fields.
    """

    df = pd.read_csv(csv_path)

    def safe_json(x):
        if x is None:
            return None

        # pandas NaN
        if isinstance(x, float) and math.isnan(x):
            return None

        # already parsed
        if isinstance(x, (dict, list)):
            return x

        if isinstance(x, str):
            try:
                parsed = json.loads(x)

                # handle double-encoded JSON
                if isinstance(parsed, str):
                    return json.loads(parsed)

                return parsed
            except:
                return None

        return None

    json_cols = ["descriptions", "configurations", "metrics", "weaknesses"]

    for col in json_cols:
        if col in df.columns:
            df[col] = df[col].apply(safe_json)

    return df