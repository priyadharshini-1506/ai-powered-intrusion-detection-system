import smtplib

def send_email(alert_msg):
    sender   = "your_email@gmail.com"
    password = "your_app_password"
    receiver = "receiver@gmail.com"

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(sender, password)
    server.sendmail(sender, receiver, alert_msg)
    server.quit()
