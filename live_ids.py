from scapy.all    import sniff, IP
from predictor    import predict
from risk_engine  import get_risk
from alert_engine import get_alert
from ip_blocker   import block_ip
from datetime     import datetime
from rich.console import Console
from rich.panel   import Panel
from rich.text    import Text
 
# ══════════════════════════════════════════════
# CYBERSENTINEL IDS — live_ids.py
# Theme: Microsoft Defender / Elastic Dark Theme
# ══════════════════════════════════════════════
 
# Background set to #0F172A, base text set to #F8FAFC
console = Console(style="color(#f8fafc) on color(#0f172a)")
 
CORAL     = "#22C55E"   # primary accent — defender green
ORANGE    = "#16a34a"   # high-risk
AMBER     = "#475569"   # medium / warning
SAND      = "#334155"   # nominal / muted-dark
MUTED     = "#94A3B8"   # labels & subdued text (secondary text)
 
pkt_count   = 0
blocked_ips = set()
 
# ── Banner ──────────────────────────────────────
 
def print_banner():
    t = Text()
    t.append("\n  ⬡ ", style=f"bold {CORAL}")
    t.append("CYBERSENTINEL IDS", style="bold #F8FAFC")
    t.append("  —  Smart Industry · Live IDS\n", style=MUTED)
    t.append(f"  {'─' * 52}\n", style=MUTED)
    t.append("  MODEL  ", style=MUTED);  t.append("Extra Trees  ", style="#F8FAFC")
    t.append("DATASET  ", style=MUTED);  t.append("CICIoT2023  ", style="#F8FAFC")
    t.append("CLASSES  ", style=MUTED);  t.append("10 ATK\n",      style="#F8FAFC")
    t.append(f"  {'─' * 52}\n", style=MUTED)
    console.print(Panel(t, border_style=SAND, padding=(0, 1)))
    console.print()
 
# ── Threat score helper ──────────────────────────
 
def get_threat(risk, alert, attack):
    level = {"SAFE": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    k     = next((k for k in level if k in alert.upper()), "SAFE")
    score = round(risk * 0.7 + level[k] * 10, 2)
    if attack.lower() == "normal":
        score = min(score * 0.2, 15)
    score = min(score, 100)
    if score > 80: return score, CORAL,  "CRITICAL"
    if score > 60: return score, ORANGE, "HIGH"
    if score > 30: return score, AMBER,  "MEDIUM"
    return score, SAND, "NOMINAL"
 
# ── Packet processor ─────────────────────────────
 
def process_packet(packet):
    global pkt_count
 
    if not packet.haslayer(IP):
        return
 
    pkt_count  += 1
    src_ip      = packet[IP].src
    dst_ip      = packet[IP].dst
    features    = packet.summary()
    ts          = datetime.now().strftime("%H:%M:%S.%f")[:-3]
 
    attack, prob        = predict(features)
    risk                = get_risk(prob, attack)
    alert               = get_alert(risk)
    score, color, label = get_threat(risk, alert, attack)
 
    # ── Live log row ────────────────────────────
    row = Text()
    row.append(f"  {ts}  ",              style=MUTED)
    row.append(f"PKT {pkt_count:05d}  ", style=f"bold {MUTED}")
    row.append(f"{src_ip:<18}",          style="#F8FAFC")
    row.append("→  ",                    style=MUTED)
    row.append(f"{dst_ip:<18}",          style=MUTED)
    row.append(f"{attack:<26}",          style=f"bold {color}")
    row.append(f"RISK {risk:5.1f}%  ",   style=color)
    row.append(f"[{label}]",             style=f"bold {color}")
    console.print(row)
 
    # ── Critical block ───────────────────────────
    if risk > 80:
        block_ip(src_ip)
        blocked_ips.add(src_ip)
 
        alert_t = Text()
        alert_t.append(f"\n  🔴 CRITICAL — IP BLOCKED\n",    style=f"bold {CORAL}")
        alert_t.append(f"  SOURCE IP    : ",                  style=MUTED)
        alert_t.append(f"{src_ip}\n",                         style="bold #F8FAFC")
        alert_t.append(f"  ATTACK CLASS : ",                  style=MUTED)
        alert_t.append(f"{attack}\n",                         style="bold #F8FAFC")
        alert_t.append(f"  RISK         : ",                  style=MUTED)
        alert_t.append(f"{risk:.1f}%\n",                      style=f"bold {CORAL}")
        alert_t.append(f"  SCORE        : ",                  style=MUTED)
        alert_t.append(f"{score:.1f}/100\n",                  style="#F8FAFC")
        alert_t.append(f"  TOTAL BLOCKED: ",                  style=MUTED)
        alert_t.append(f"{len(blocked_ips)}",                 style=f"bold {CORAL}")
        console.print(Panel(alert_t, border_style=SAND, padding=(0, 1)))
        console.print()
 
    elif score > 60:
        warn = Text()
        # Fixed the broken character layout below:
        warn.append(f"  🟠 HIGH RISK  {src_ip}  →  {attack}  "
                    f"SCORE {score:.1f}", style=f"bold {ORANGE}")
        console.print(Panel(warn, border_style=SAND, padding=(0, 0)))
        console.print()
 
# ── Entry point ──────────────────────────────────
 
if __name__ == "__main__":
    print_banner()
 
    hdr = Text()
    hdr.append(
        f"  {'TIMESTAMP':<14}{'PKT':<10}{'SRC IP':<18}   "
        f"{'DST IP':<18}{'ATTACK CLASS':<26}{'RISK':<12}STATUS",
        style=f"bold {MUTED}"
    )
    console.print(hdr)
    console.print(Text(f"  {'─' * 108}", style=MUTED))
    console.print()
    console.print(Text(f"  ⬡ LIVE SNIFFING — CTRL+C TO STOP\n", style=f"bold {CORAL}"))
 
    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        console.print()
        console.print(Text(
            f"  ⬡ STOPPED  |  PACKETS: {pkt_count}  |  BLOCKED: {len(blocked_ips)}",
            style=f"bold {CORAL}"
        ))
        console.print()