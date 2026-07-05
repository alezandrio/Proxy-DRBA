#!/usr/bin/env python3
"""
Constroi o botsv2_risk_events_master.csv a partir dos CSV exportados
das regras de correlacao SPL (um CSV por regra).

Saida normalizada (formato que drba_densityfn.py espera):
    _time, entity, risk_object_type, risk_score, rule_name

Cada regra exporta colunas diferentes; o mapa RULES abaixo diz, por
ficheiro, qual a coluna que serve de 'entity'. Ajusta os nomes dos
ficheiros / colunas conforme os teus exports reais.
"""

import re
from pathlib import Path

import pandas as pd

# pasta onde estao os CSV das regras (ajusta)
CSV_DIR = Path("/Users/alezandrio/Desktop/Faculdade/GECAD/Splunk/CSV")
OUT = CSV_DIR / "analyst_no_DNS.csv"

# por regra: ficheiro -> coluna que identifica a entidade.
# todas ja trazem _time, risk_score e rule_name dos teus eval finais.
RULES = {
    #"DNS_Query_Length_With_High_Standard_Deviation_attack.csv":            "entity",
    "HTTP_Scripting_Tool_User_Agent.csv":                           "entity",
    "Protocols_Passing_Authentication_In_Cleartext.csv":            "entity",
    "Windows_AD_Privileged_Group_Modification.csv":                 "entity",
    "Windows_Multiple_Users_Fail_To_Authenticate_Wth_ExplicitCredentials.csv": "entity",
    "Windows_Special_Privileged_Logon_On_Multiple_Hosts.csv":       "entity",
    "Windows_Administrative_Shares_Accessed_On_Multiple_Hosts.csv":        "entity",
}

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def entity_type(e: str) -> str:
    """user vs system (IP, hostname, conta de maquina)."""
    e = str(e)
    if IP_RE.match(e) or ":" in e:                      # IPv4/IPv6
        return "system"
    if e.lower().endswith(".local") or e.startswith("wrk-") or "$" in e:
        return "system"
    return "user"


def clean_entity(val) -> str:
    # apanha "service3\n-" -> "service3"; remove dominio se quiseres uniformizar
    return str(val).split("\n")[0].strip().strip('"')


def main():
    frames = []
    for fname, ent_col in RULES.items():
        path = CSV_DIR / fname
        if not path.exists():
            print(f"[aviso] em falta: {fname}")
            continue
        df = pd.read_csv(path)
        if ent_col not in df.columns:
            print(f"[aviso] {fname}: sem coluna '{ent_col}', ignorado")
            continue
        out = pd.DataFrame({
            "_time": df["_time"],
            "entity": df[ent_col].map(clean_entity),
            "risk_score": df.get("risk_score", 20),
            "rule_name": df.get("rule_name", fname.replace(".csv", "")),
        })
        out = out[~out["entity"].isin(["", "-", "nan"])]
        frames.append(out)
        print(f"[ok] {fname}: {len(out)} eventos")

    master = pd.concat(frames, ignore_index=True)
    master["_time"] = pd.to_datetime(master["_time"], format="ISO8601")
    master["risk_object_type"] = master["entity"].map(entity_type)
    master = master.sort_values("_time").reset_index(drop=True)

    master = master[["_time", "entity", "risk_object_type",
                     "risk_score", "rule_name"]]
    master.to_csv(OUT, index=False)

    print(f"\nMaster: {len(master)} eventos | "
          f"{master['entity'].nunique()} entidades | "
          f"{master['_time'].dt.date.min()} -> {master['_time'].dt.date.max()}")
    print(master["risk_object_type"].value_counts().to_string())
    print(f"\nGravado: {OUT}")


if __name__ == "__main__":
    main()