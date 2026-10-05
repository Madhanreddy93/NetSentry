# NetSentry

NetSentry is a simulation-first dashboard that spots unusual network behavior and explains its best-guess attack type. It creates synthetic packets locally, can analyze an uploaded CSV or existing PCAP, and displays possible firewall rules as text. It never sends traffic or runs generated commands. Detection uses packet headers and traffic statistics only; encrypted payloads are not inspected.

## Architecture

```text
Synthetic traffic / uploaded CSV or PCAP
                 |
                 v
       Rolling window features
                 |
                 v
 Normal-only Isolation Forest / One-Class SVM
                 |
          anomaly score + flag
                 |
       explainable attack rules
          /              \
   live dashboard    iptables text only
```

## Setup

Requires Python 3.10 or newer.

```powershell
cd netsentry
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run

```powershell
streamlit run app.py
```

The first launch trains and saves a model using normal synthetic traffic. To train and evaluate from the command line:

```powershell
python -m netsentry.model --train --evaluate
```

Run unit tests with `pytest`.

## Demo

1. Open the dashboard; it starts in live simulation mode with normal traffic.
2. Confirm the green `ALL NORMAL` banner and watch the packet-rate chart update.
3. Select `SYN Flood` in the scenario dropdown and click `Inject attack now`.
4. The dashboard flags the unusual window, shows a SYN flood explanation, and displays generated iptables text plus the SYN-cookies note.
5. Use the copy control in the code block or download `block_rules.sh`. These commands are never run by NetSentry.
6. Click `Reset` to clear the current in-memory replay.

## Screenshots

Screenshot placeholder: add a dashboard capture here after running the app.

## Limitations and choices

- The simulator uses deterministic, invented traffic and documentation/test address ranges. They are not real attacker indicators.
- Classification is a transparent heuristic after the model marks a window unusual; a label is an explanation, not proof of an attack.
- The sensitivity setting controls a quantile threshold calibrated against normal training scores. Raising it flags more windows and can increase false alarms.
- Evaluation metrics are generated from one seeded mixed synthetic scenario and are not a promise of production performance.
- Uploaded CSV files need timestamp, source IP, destination port, protocol, and packet-size columns; common NSL-KDD/CIC-style header spellings are normalized where practical. Labels are used only for evaluation context.
- PCAP support reads an existing capture offline with Scapy. This prototype does not capture live interfaces or decode encrypted application data.
- Firewall rules are examples for review, not universal deployment guidance. Private, loopback, and reserved addresses are flagged. The application has no code path that executes these rules.

## Future work

Add richer flow aggregation, a reviewed NSL-KDD/CIC-IDS evaluation workflow, threshold calibration reports, and an optional read-only API. Any live capture integration should require explicit operator consent and remain passive.