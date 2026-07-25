def get_alert(risk):
    if   risk >= 90: return "🔴 CRITICAL"
    elif risk >= 70: return "🟠 HIGH"
    elif risk >= 40: return "🟡 MEDIUM"
    else:            return "🟢 SAFE"