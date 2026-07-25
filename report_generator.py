from datetime import datetime

def generate_report(logs):
    total    = len(logs)
    critical = sum(1 for x in logs if x["risk"] > 90)
    high     = sum(1 for x in logs if 70 < x["risk"] <= 90)
    medium   = sum(1 for x in logs if 40 < x["risk"] <= 70)
    safe     = sum(1 for x in logs if x["risk"] <= 40)
    sample   = logs[-5:] if len(logs) > 5 else logs

    report = f"""
╔══════════════════════════════════════════╗
       SOC INCIDENT REPORT
       Generated : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
╚══════════════════════════════════════════╝

TOTAL EVENTS   : {total}
─────────────────────────────────────────
  🔴 CRITICAL  : {critical}
  🟠 HIGH      : {high}
  🟡 MEDIUM    : {medium}
  🟢 SAFE      : {safe}
─────────────────────────────────────────
LAST 5 EVENTS  :
{sample}
"""
    return report
