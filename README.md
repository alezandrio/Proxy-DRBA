# Pipeline de Avaliação DRBA — BOTSv2

Avaliação quantitativa (Precision / Recall / F1) de *Dynamic Risk-Based
Alerting* (DRBA) sobre o dataset público **Splunk BOTSv2**, usando um proxy
`scipy` da `DensityFunction` do MLTK.

O fluxo tem duas etapas encadeadas:

```
CSVs por regra SPL ──▶ Build_master.py ──▶ master.csv ──▶ drba_densityfn.py ──▶ ablação + métricas
```

O primeiro script **normaliza** os eventos exportados das regras de correlação
num formato único; o segundo **consome** esse formato para calibrar thresholds
por entidade e comparar as várias configurações contra o *ground truth*.

---

## 1. `Build_master.py` — construção do master de eventos de risco

### O que faz
Junta os CSV exportados de cada regra de correlação SPL (um ficheiro por regra)
num único `master` normalizado, no formato que o `drba_densityfn.py` espera:

```
_time, entity, risk_object_type, risk_score, rule_name
```

### Como funciona

**Mapa de regras (`RULES`).** Cada regra exporta colunas com nomes diferentes,
por isso o dicionário `RULES` diz, por ficheiro, qual a coluna que serve de
`entity`. A entrada da regra de DNS está comentada — o output é
`analyst_no_DNS.csv`, ou seja, esta variante **exclui os eventos de DNS**.
Para incluir DNS, basta descomentar a linha respetiva.

**Limpeza de entidades (`clean_entity`).** Alguns exports trazem valores sujos
com quebras de linha (ex.: `"service3\n-"`). A função corta na primeira linha,
tira espaços e aspas, ficando só `service3`.

**Tipo de entidade (`entity_type`).** Classifica cada entidade como `system` ou
`user`, para preencher `risk_object_type`:
- `system` — se for IPv4/IPv6 (regex `IP_RE` ou presença de `:`), se acabar em
  `.local`, começar por `wrk-`, ou contiver `$` (conta de máquina do AD).
- `user` — tudo o resto.

**Montagem e ordenação.** Concatena todos os frames, converte `_time` para
`datetime` (formato ISO8601), ordena cronologicamente e grava o CSV. No fim
imprime um resumo: total de eventos, nº de entidades únicas, intervalo temporal
e a contagem `system` vs `user`.

### Robustez
- Ficheiro em falta → aviso e salta (`[aviso] em falta: ...`).
- Coluna de entidade em falta → aviso e ignora essa regra.
- `risk_score` ausente → default `20`; `rule_name` ausente → nome do ficheiro.
- Filtra entidades vazias / `-` / `nan`.

### Uso
```bash
python3 Build_master.py
```
Os caminhos estão fixos no topo do script (`CSV_DIR`, `OUT`); ajusta conforme a
tua estrutura de pastas antes de correr.

### Output
`analyst_no_DNS.csv` — o **master** de entrada para a etapa seguinte.

> **Nota:** para gerar o par que o `drba_densityfn.py` precisa, corre este
> script duas vezes (ou adapta-o): uma para o master **completo** (todos os
> eventos) e outra só com os eventos **do ataque** (*attack-only*), que serve de
> ground truth.

---

## 2. `drba_densityfn.py` — ablação e métricas

### O que faz
Recebe dois masters — o **completo** e o **attack-only** — e corre um **estudo
de ablação** que isola o contributo de cada salvaguarda do DRBA, comparando 4
configurações incrementais contra um baseline estático (SRBA).

### As configurações avaliadas

| # | Config | Descrição |
|---|--------|-----------|
| 0 | **SRBA** | Threshold estático fixo (`STATIC_THRESHOLD = 100`). Baseline. |
| 1 | **DRBA base** | Densidade por entidade, **sem** salvaguardas. |
| 2 | **DRBA +cold** | Adiciona **piso** de cold-start (baixa cardinalidade). |
| 3 | **DRBA +cold+cap** | Adiciona **teto** global (`μ + k·σ`). |

O MLTK 0.08 nativo é avaliado à parte no Splunk; aqui gera-se o lado do proxy
para comparar contra esse valor.

### Como funciona

**Carregamento e normalização (`load_master`, `normalize_entity`).**
Lê o master, converte `_time`, cria a coluna `day` (dia normalizado) e uniformiza
as entidades: minúsculas, remove domínio `frothly\x → x` e descarta linhas
vazias.

**Agregação contígua (`aggregate_contiguous`).** Soma o `risk_score` por
`(entity, day)` e depois **preenche com zeros** todos os dias em falta no
intervalo completo (`MultiIndex` entidade × dias). Este *full contiguity
zero-fill* corrige o enviesamento de seleção — sem ele, só se veriam os dias
"ativos" e a distribuição por entidade ficaria distorcida.

**Motor de densidade (`fit_best`, `upper_threshold`).** Para cada entidade
ajusta a melhor distribuição por *log-likelihood* (sem penalização AIC) entre
`normal`, `expon`, `beta` e `kde`. O threshold é o ponto acima da mediana onde a
densidade cai abaixo de `DENS_THR = 0.01` — ou seja, onde o risco deixa de ser
"típico" e passa a *outlier*.

**Construção dos thresholds (`build_thresholds`).** Calcula, por entidade, os
três thresholds das variantes DRBA:
- `thr_base` — densidade pura, sem salvaguardas.
- `thr_cold` — se a entidade tem menos de `MIN_DAYS = 5` dias ativos, usa o piso
  `HYBRID_FLOOR = 50`; senão, usa a densidade.
- `thr_cap` — aplica o teto global `μ + CEILING_K·σ` (`CEILING_K = 3`) por cima
  do `thr_cold`.

O piso protege entidades com poucos dados (a densidade seria pouco fiável); o
teto evita thresholds absurdamente altos que nunca disparariam.

**Ground truth (`label_ground_truth`).** Marca como `malicious` cada par
`(entity, day)` presente no master attack-only.

**Matriz de confusão (`confusion`).** Calcula TP / FP / FN / TN e daí
Accuracy, Precision, Recall e F1. A avaliação é feita **apenas sobre pares com
risco > 0** — os zeros sintéticos do zero-fill servem para calibrar a
distribuição, não para inflar os TN.

**Avaliação (`evaluate`).** Aplica a regra de alerta de cada config
(`daily_risk ≥ threshold`), imprime a tabela comparativa das 4 configurações e
adiciona um rótulo auditável (`TP`/`FP`/`FN`/`TN`) por par para a config final
(`cap`).

### Parâmetros (topo do script)

| Parâmetro | Valor | Papel |
|-----------|-------|-------|
| `STATIC_THRESHOLD` | 100 | Threshold do baseline SRBA. |
| `HYBRID_FLOOR` | 50 | Piso cold-start. |
| `MIN_DAYS` | 5 | Dias ativos mínimos para ajustar distribuição. |
| `DENS_THR` | 0.01 | Limiar de densidade para considerar outlier. |
| `GRID_N` | 2000 | Resolução da grelha de avaliação da densidade. |
| `CEILING_K` | 3 | Multiplicador do desvio no teto global. |

### Uso
```bash
python3 drba_densityfn.py full_master.csv attack_only_master.csv
python3 drba_densityfn.py full_master.csv attack_only_master.csv --out resultado.csv
```

### Output
- **Consola:** distribuições escolhidas, contagem de entidades cold-start /
  capped, tamanho do ground truth e a tabela de métricas das 4 configurações.
- **CSV** (`botsv2_ablation.csv` por default): dataset auditável, um par por
  linha, com o threshold aplicado, a decisão de alerta e o rótulo
  TP/FP/FN/TN da config final.

---

## Dependências
```
python >= 3.8
pandas
numpy
scipy
```
```bash
pip install pandas numpy scipy
```

## Resumo do fluxo
1. Exportar os CSV das regras de correlação SPL do Splunk.
2. `Build_master.py` → normaliza tudo num master (`_time, entity,
   risk_object_type, risk_score, rule_name`).
3. Gerar dois masters: completo e attack-only (ground truth).
4. `drba_densityfn.py` → calibra thresholds por entidade, corre a ablação e
   produz as métricas Precision / Recall / F1 mais o CSV auditável.