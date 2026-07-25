def get_prevention(attack):
    prevention_map = {
        "Backdoor": [
            "Scan systems for unauthorized remote access tools",
            "Monitor outbound connections to unknown IPs",
            "Enforce application whitelisting policies",
            "Audit user accounts for privilege escalation",
        ],
        "DDoS": [
            "Enable DDoS mitigation and scrubbing service",
            "Apply rate limiting per source IP",
            "Block suspicious IPs via firewall rules",
            "Monitor for abnormal traffic volume spikes",
        ],
        "DoS": [
            "Enable SYN cookies and connection limits",
            "Apply rate limiting on affected services",
            "Configure firewall to drop malformed packets",
            "Use load balancing to distribute traffic",
        ],
        "Injection": [
            "Sanitize and validate all user inputs",
            "Use parameterized queries and prepared statements",
            "Enable WAF rules to block injection patterns",
            "Audit application code for vulnerable endpoints",
        ],
        "MITM": [
            "Enable Dynamic ARP Inspection (DAI)",
            "Use static ARP entries for critical hosts",
            "Enforce HTTPS and certificate pinning",
            "Monitor ARP tables for spoofing anomalies",
        ],
        "Normal": [
            "No threat detected — continue monitoring",
            "Maintain baseline traffic logging",
            "Ensure IDS signatures are up to date",
            "Review periodic audit logs for anomalies",
        ],
        "Password": [
            "Enforce account lockout after failed attempts",
            "Enable multi-factor authentication (MFA)",
            "Rate-limit login attempts per IP",
            "Alert on repeated failed authentication events",
        ],
        "Ransomware": [
            "Isolate affected systems from the network immediately",
            "Restore files from clean offline backups",
            "Scan all endpoints for ransomware payloads",
            "Block known ransomware C2 server IPs",
        ],
        "Scanning": [
            "Close all unused ports and services",
            "Enable port-scan detection rules in IDS",
            "Configure firewall to block scanner IPs",
            "Log and alert on repeated scan attempts",
        ],
        "XSS": [
            "Implement Content Security Policy (CSP) headers",
            "Sanitize and encode all user-supplied output",
            "Enable WAF rules targeting XSS payloads",
            "Audit web application templates for unsafe rendering",
        ],
    }
 
    steps = prevention_map.get(
        attack,
        [
            "Monitor all network traffic continuously",
            "Isolate affected systems immediately",
            "Review event logs for anomalies",
            "Update firewall rules for this pattern",
        ],
    )
 
    # Match theme: #0F172A bg, #1E293B card, #334155 border, #22C55E accent
    is_normal = attack.lower() == "normal"
    accent    = "#22C55E" if is_normal else "#22C55E"
    badge_bg  = "rgba(34,197,94,0.15)"
 
    items_html = "".join(
        f'<div style="display:flex;align-items:flex-start;gap:12px;'
        f'padding:10px 0;border-bottom:1px solid #334155;">'
        f'<span style="color:#22C55E;font-size:13px;margin-top:1px;font-weight:700;'
        f'flex-shrink:0;font-family:Helvetica,sans-serif;">→</span>'
        f'<span style="color:#CBD5E1;font-size:13px;font-family:Helvetica,sans-serif;'
        f'line-height:1.6;">{step}</span>'
        f'</div>'
        for step in steps
    )
 
    html = f"""
<div style="
    border: 1px solid #334155;
    background: #1E293B;
    border-radius: 8px;
    padding: 20px 22px;
    margin-top: 4px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;">
    <span style="
        color: #94A3B8;
        font-size: 10px;
        font-weight: 700;
        font-family: Helvetica, sans-serif;
        text-transform: uppercase;
        letter-spacing: 2px;
    ">⚠ Attack Detected</span>
    <span style="
        background: {badge_bg};
        border: 1px solid #22C55E;
        border-radius: 4px;
        padding: 2px 10px;
        color: #22C55E;
        font-size: 11px;
        font-family: Helvetica, sans-serif;
        font-weight: 700;
        letter-spacing: 1px;
        text-transform: uppercase;
    ">{attack}</span>
  </div>
  <div style="
      color: #475569;
      font-size: 10px;
      font-family: Helvetica, sans-serif;
      text-transform: uppercase;
      letter-spacing: 2px;
      margin-bottom: 12px;
      font-weight: 700;
  ">Recommended Mitigation Steps</div>
  {items_html}
</div>
"""
    return html
 