from twilio.rest import Client

def send_sms(msg):
    client = Client("YOUR_TWILIO_SID", "YOUR_TWILIO_AUTH_TOKEN")
    client.messages.create(
        body=msg,
        from_="+1234567890",
        to="+91XXXXXXXXXX",
    )
