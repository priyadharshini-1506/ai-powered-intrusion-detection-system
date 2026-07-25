from predictor       import predict
from risk_engine     import get_risk
from alert_engine    import get_alert
from email_alert     import send_email

def process_packet(row):
    attack, prob = predict(row)
    risk         = get_risk(prob, attack)
    alert        = get_alert(risk)

    result = {
        "attack": attack,
        "risk":   risk,
        "alert":  alert,
    }

    if risk > 80:
        send_email(f"CRITICAL ALERT: {attack} — Risk: {risk:.1f}%")

    return result