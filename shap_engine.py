import shap
import joblib
import numpy as np
import pandas as pd
 
model = joblib.load(r"D:\files\extra_trees.pkl")
 
explainer = shap.TreeExplainer(model)
 
def get_top_features(row):
    shap_values = explainer.shap_values(row)
    shap_values = np.array(shap_values)
 
    if len(shap_values.shape) == 3:
        values = shap_values[0][0]
    elif len(shap_values.shape) == 2:
        values = shap_values[0]
    else:
        values = shap_values
 
    values        = np.abs(values)
    feature_names = list(row.columns)
    min_len       = min(len(feature_names), len(values))
    feature_names = feature_names[:min_len]
    values        = values[:min_len]
 
    df = pd.DataFrame({
        "Feature":    feature_names,
        "Importance": values,
    })
    df = df.sort_values("Importance", ascending=False).head(5)
    return df