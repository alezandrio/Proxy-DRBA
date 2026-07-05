#!/usr/bin/env python3
"""
Fase 3+4 - DRBA via proxy do Splunk MLTK DensityFunction (sem MLTK).

ABLATION STUDY - avalia 4 configuracoes incrementais para isolar o
contributo de cada salvaguarda:

  (0) SRBA            : threshold estatico fixo (baseline).
  (1) DRBA base       : densidade por entidade, SEM salvaguardas.
                        (cold-start desligado -> distribuicao mesmo com
                         poucos dados; sem teto).
  (2) DRBA + cold     : adiciona PISO para baixa cardinalidade.
  (3) DRBA + cold+cap : adiciona TETO (mu + k*sigma global).

O MLTK 0.08 nativo e' avaliado separadamente no Splunk; aqui gera-se o
lado do proxy para comparar contra esse valor.

Uso:
  python3 drba_densityfn.py full_master.csv attack_only_master.csv
"""

import argparse
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

warnings.filterwarnings("ignore")

# ---- parametros -------------------------------------------------------------
STATIC_THRESHOLD = 100     # SRBA
HYBRID_FLOOR     = 50      # PISO cold-start
MIN_DAYS         = 5       # dias ativos minimos p/ ajustar distribuicao
DENS_THR         = 0.01    # limiar de densidade p/ outlier
GRID_N           = 2000    # resolucao da grelha
CEILING_K        = 3       # TETO = media_global + CEILING_K * desvio_global


# ---- carregamento e normalizacao -------------------------------------------
def normalize_entity(s: pd.Series) -> pd.Series:
    s = s.astype(str).str.split("\n").str[0].str.strip()
    s = s.str.replace(r"^[^\\]+\\", "", regex=True)   # frothly\x -> x
    return s.str.lower()


def load_master(path: Path) -> pd.DataFrame:
    m = pd.read_csv(path)
    m["_time"] = pd.to_datetime(m["_time"], format="ISO8601")
    m["day"] = m["_time"].dt.normalize()
    m["entity"] = normalize_entity(m["entity"])
    return m[~m["entity"].isin(["", "-", "nan"])]


def aggregate_contiguous(m: pd.DataFrame) -> pd.DataFrame:
    daily = (m.groupby(["entity", "day"])["risk_score"]
               .sum().reset_index(name="daily_risk"))
    full = pd.date_range(daily["day"].min(), daily["day"].max(), freq="D")
    ents = daily["entity"].unique()
    grid = (pd.MultiIndex.from_product([ents, full], names=["entity", "day"])
              .to_frame(index=False))
    cont = grid.merge(daily, on=["entity", "day"], how="left")
    cont["daily_risk"] = cont["daily_risk"].fillna(0.0)
    return cont


# ---- motor DensityFunction (proxy scipy) -----------------------------------
def fit_best(x: np.ndarray):
    x = np.asarray(x, float)
    cands = []
    try:
        mu, sd = stats.norm.fit(x)
        cands.append(("normal", stats.norm.logpdf(x, mu, sd).sum(), (mu, sd)))
    except Exception:
        pass
    try:
        lo, sc = stats.expon.fit(x)
        cands.append(("expon", stats.expon.logpdf(x, lo, sc).sum(), (lo, sc)))
    except Exception:
        pass
    try:
        mx = x.max() or 1.0
        xn = np.clip(x / mx, 1e-6, 1 - 1e-6)
        a, b, _, _ = stats.beta.fit(xn, floc=0, fscale=1)
        cands.append(("beta", stats.beta.logpdf(xn, a, b).sum(), (a, b, mx)))
    except Exception:
        pass
    try:
        if np.ptp(x) > 0:
            k = stats.gaussian_kde(x)
            cands.append(("kde", float(np.log(k(x) + 1e-12).sum()), k))
    except Exception:
        pass
    if not cands:
        return None
    name, _, params = max(cands, key=lambda t: t[1])
    return name, params


def upper_threshold(name, params, x: np.ndarray) -> float:
    grid = np.linspace(0, x.max() * 1.5 + 1, GRID_N)
    if name == "normal":
        mu, sd = params
        dens = stats.norm.pdf(grid, mu, sd)
    elif name == "expon":
        lo, sc = params
        dens = stats.expon.pdf(grid, lo, sc)
    elif name == "beta":
        a, b, mx = params
        dens = stats.beta.pdf(np.clip(grid / mx, 1e-6, 1 - 1e-6), a, b)
    elif name == "kde":
        dens = params(grid)
    med = np.median(x)
    upper = grid[(grid > med) & (dens < DENS_THR)]
    return float(upper.min()) if len(upper) else float(grid.max())


def build_thresholds(cont: pd.DataFrame) -> pd.DataFrame:
    """
    Calcula, por entidade, o threshold em CADA uma das 3 variantes DRBA:
      thr_base : densidade sempre (sem cold-start, sem teto)
      thr_cold : com piso cold-start p/ baixa cardinalidade
      thr_cap  : com piso cold-start + teto global
    """
    pos = cont.loc[cont["daily_risk"] > 0, "daily_risk"].values
    ceiling = float(pos.mean() + CEILING_K * pos.std())

    rows = []
    for ent, g in cont.groupby("entity"):
        x = g["daily_risk"].values
        active = int((x > 0).sum())

        # ajuste de densidade -- tenta sempre (para a variante base)
        fb = fit_best(x)
        if fb is not None:
            name, params = fb
            raw_thr = upper_threshold(name, params, x)
        else:
            name, raw_thr = "-", float(STATIC_THRESHOLD)

        # (1) BASE: densidade pura, sem qualquer salvaguarda
        thr_base = raw_thr

        # (2) COLD: se poucos dias, usa piso; senao densidade
        if active < MIN_DAYS:
            thr_cold = float(HYBRID_FLOOR)
            mode = "cold-start"
        else:
            thr_cold = raw_thr
            mode = "dynamic"

        # (3) CAP: cold-start + teto por cima
        thr_cap = min(thr_cold, ceiling)
        if active >= MIN_DAYS and raw_thr > ceiling:
            mode_cap = "capped"
        else:
            mode_cap = mode

        rows.append((ent, name, active,
                     round(thr_base, 1), round(thr_cold, 1),
                     round(thr_cap, 1), mode_cap, float(x.max())))

    return pd.DataFrame(rows, columns=[
        "entity", "distro", "active_days",
        "thr_base", "thr_cold", "thr_cap", "mode", "max_risk"]), ceiling


# ---- ground truth + matriz de confusao -------------------------------------
def label_ground_truth(cont: pd.DataFrame, atk: pd.DataFrame):
    mal = atk.groupby(["entity", "day"]).size().reset_index(name="atk_events")
    mal_keys = set(zip(mal["entity"], mal["day"]))
    cont["malicious"] = [(e, d) in mal_keys
                         for e, d in zip(cont["entity"], cont["day"])]
    return cont, len(mal_keys)


def confusion(df: pd.DataFrame, alert_col: str) -> dict:
    tp = int((df.malicious & df[alert_col]).sum())
    fn = int((df.malicious & ~df[alert_col]).sum())
    fp = int((~df.malicious & df[alert_col]).sum())
    tn = int((~df.malicious & ~df[alert_col]).sum())
    acc = (tp + tn) / (tp + tn + fp + fn) if (tp+tn+fp+fn) else float("nan")
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    f1 = (2 * prec * rec / (prec + rec)
          if prec and rec and not np.isnan(prec) and not np.isnan(rec)
          else float("nan"))
    return dict(TP=tp, FN=fn, FP=fp, TN=tn,
                acc=acc, precision=prec, recall=rec, f1=f1)


# ---- avaliacao --------------------------------------------------------------
def evaluate(cont, thr, ceiling, n_mal):
    cont = cont.merge(
        thr[["entity", "thr_base", "thr_cold", "thr_cap", "mode", "distro"]],
        on="entity")

    # decisao de alerta por configuracao
    cont["srba"]   = cont["daily_risk"] >= STATIC_THRESHOLD
    cont["base"]   = cont["daily_risk"] >= cont["thr_base"]
    cont["cold"]   = cont["daily_risk"] >= cont["thr_cold"]
    cont["cap"]    = cont["daily_risk"] >= cont["thr_cap"]

    real = cont[cont["daily_risk"] > 0].copy()   # exclui zeros sinteticos

    print("=== distribuicoes escolhidas ===")
    print(thr["distro"].value_counts().to_string())
    n_cold = int((thr["mode"] == "cold-start").sum())
    n_capped = int((thr["mode"] == "capped").sum())
    print(f"\nTeto absoluto (mu+{CEILING_K}sigma global) = {ceiling:.1f}")
    print(f"Entidades cold-start: {n_cold}  |  capped: {n_capped}")
    print(f"Ground truth: {n_mal} pares maliciosos")
    print(f"Universo avaliado: {len(real)} pares com risco>0\n")

    configs = [
        ("(0) SRBA            ", "srba"),
        ("(1) DRBA base       ", "base"),
        ("(2) DRBA +cold      ", "cold"),
        ("(3) DRBA +cold+cap  ", "cap"),
    ]

    print(f"{'config':22s} {'alerts':>6s} {'TP':>4s} {'FP':>4s} "
          f"{'FN':>4s} {'TN':>4s} {'prec':>6s} {'rec':>6s} "
          f"{'F1':>6s} {'acc':>6s}")
    print("-" * 88)
    results = {}
    for label, col in configs:
        m = confusion(real, col)
        n_alert = int(real[col].sum())
        results[label.strip()] = m
        print(f"{label:22s} {n_alert:6d} {m['TP']:4d} {m['FP']:4d} "
              f"{m['FN']:4d} {m['TN']:4d} {m['precision']:6.3f} "
              f"{m['recall']:6.3f} {m['f1']:6.3f} {m['acc']:6.3f}")
    print()

    # rotulo auditavel da config final (cap) -- condicoes exclusivas
    real["label"] = np.select(
        [real.malicious & real["cap"],      # TP
         ~real.malicious & real["cap"],     # FP
         real.malicious & ~real["cap"]],    # FN
        ["TP", "FP", "FN"], default="TN")
    return real


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("full_master")
    ap.add_argument("attack_master")
    ap.add_argument("--out", default="botsv2_ablation.csv")
    args = ap.parse_args()

    full = load_master(Path(args.full_master))
    atk = load_master(Path(args.attack_master))

    cont = aggregate_contiguous(full)
    thr, ceiling = build_thresholds(cont)
    cont, n_mal = label_ground_truth(cont, atk)
    real = evaluate(cont, thr, ceiling, n_mal)

    out = Path(args.full_master).resolve().parent / args.out
    real.sort_values(["malicious", "daily_risk"],
                     ascending=False).to_csv(out, index=False)
    print(f"Gravado (auditavel): {out}")


if __name__ == "__main__":
    main()
