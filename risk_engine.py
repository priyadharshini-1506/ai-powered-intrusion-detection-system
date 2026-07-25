import numpy as np
 
def get_risk(prob, attack=None):
    prob        = np.array(prob).flatten()
    prob_clean  = np.clip(prob, 1e-10, 1.0)
    entropy     = -np.sum(prob_clean * np.log(prob_clean))
    max_entropy = np.log(len(prob_clean))
    uncertainty = entropy / max_entropy if max_entropy > 0 else 0
 
    top_conf = float(np.max(prob))
    risk     = top_conf * (1 - uncertainty) * 100
 
    if attack and attack.lower() == "normal":
        risk = risk * 0.15
 
    return round(risk, 2)
 