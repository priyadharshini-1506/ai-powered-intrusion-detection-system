import joblib
import numpy as np

model = joblib.load(r"D:\files\extra_trees.pkl")

labels = [
    "Backdoor",
    "DDoS",
    "DoS",
    "Injection",
    "MITM",
    "Normal",
    "Password",
    "Ransomware",
    "Scanning",
    "XSS",
]

def predict(row):
    pred     = model.predict(row)
    pred_id  = int(np.array(pred).flatten()[0])
    attack   = labels[pred_id]
    prob     = model.predict_proba(row)
    return attack, prob