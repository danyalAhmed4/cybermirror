# -*- coding: utf-8 -*-
"""
XSS Attack Detection
Dataset: Data_66_featurs.csv (67 numeric features + Label)
Run locally: python xss_attack_detection.py
Keep Data_66_featurs.csv in the same folder as this script.
"""

import time

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from imblearn.over_sampling import SMOTE
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (classification_report, accuracy_score,
                             f1_score, confusion_matrix)
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

FILE_PATH = "Data_66_featurs.csv"
RANDOM_STATE = 42
TUNE_SAMPLE = 20000        # rows used for grid search (keeps tuning fast)
DROP_DUPLICATES = True     # removes identical rows so test data isn't seen in training

# ---------------------------------------------------------------
# Step 1: Load dataset
# ---------------------------------------------------------------
data = pd.read_csv(FILE_PATH)
print("Shape:", data.shape)
print("\nLabel distribution:")
print(data["Label"].value_counts())
print("\nFirst 5 rows:")
print(data.head().to_string())

# ---------------------------------------------------------------
# Step 2: Preprocessing
# ---------------------------------------------------------------
data = data.replace([float("inf"), float("-inf")], np.nan)
data = data.fillna(data.mean(numeric_only=True))

if DROP_DUPLICATES:
    before = len(data)
    data = data.drop_duplicates()
    print(f"\nRemoved {before - len(data)} duplicate rows, {len(data)} remain")
    print(data["Label"].value_counts())

X = data.drop("Label", axis=1)
y = data["Label"]

# ---------------------------------------------------------------
# Step 3: Train-test split, then SMOTE on the TRAINING set only
# (balancing before the split would put synthetic rows in the test set)
# ---------------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
)
print("\nTrain distribution before SMOTE:")
print(y_train.value_counts())

smote = SMOTE(random_state=RANDOM_STATE)
X_train, y_train = smote.fit_resample(X_train, y_train)
print("\nTrain distribution after SMOTE:")
print(pd.Series(y_train).value_counts())

# ---------------------------------------------------------------
# Step 4: Standardize features
# ---------------------------------------------------------------
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
y_train = np.asarray(y_train)
y_test = np.asarray(y_test)

# ---------------------------------------------------------------
# Step 5: Models and hyperparameter grids
# ---------------------------------------------------------------
models = {
    "Logistic Regression": LogisticRegression(max_iter=2000, random_state=RANDOM_STATE),
    "Random Forest": RandomForestClassifier(random_state=RANDOM_STATE, n_jobs=-1),
    "Gradient Boosting": GradientBoostingClassifier(random_state=RANDOM_STATE),
    "XGBoost": XGBClassifier(eval_metric="logloss", random_state=RANDOM_STATE, n_jobs=-1),
}

param_grids = {
    "Random Forest": {
        "n_estimators": [100, 200, 300],
        "max_depth": [5, 10, 15],
        "min_samples_split": [2, 5],
    },
    "Gradient Boosting": {
        "n_estimators": [100, 200],
        "learning_rate": [0.01, 0.1],
        "max_depth": [3, 5, 7],
    },
}

rng = np.random.RandomState(RANDOM_STATE)
tune_idx = rng.choice(len(X_train_scaled),
                      size=min(TUNE_SAMPLE, len(X_train_scaled)), replace=False)

# ---------------------------------------------------------------
# Step 6: Train and evaluate
# ---------------------------------------------------------------
results, fitted = [], {}
for model_name, model in models.items():
    t0 = time.time()

    if model_name in param_grids:
        # Tune on a subsample, then refit the best settings on the full training set
        grid = GridSearchCV(model, param_grids[model_name], cv=3, n_jobs=-1, verbose=1)
        grid.fit(X_train_scaled[tune_idx], y_train[tune_idx])
        print(f"\n{model_name} best params: {grid.best_params_}")
        model = clone(model).set_params(**grid.best_params_)

    model.fit(X_train_scaled, y_train)
    y_pred = model.predict(X_test_scaled)

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted")
    results.append((model_name, acc, f1))
    fitted[model_name] = model

    print(f"\n=== Results for {model_name} ({time.time() - t0:.1f}s) ===")
    print("Accuracy:", round(acc, 4))
    print("F1 Score:", round(f1, 4))
    print("Classification Report:\n", classification_report(y_test, y_pred, digits=4))
    print("-" * 40)

res_df = pd.DataFrame(results, columns=["Model", "Accuracy", "F1"]).sort_values("F1", ascending=False)
print("\nModel comparison:")
print(res_df.to_string(index=False))

best_name = res_df.iloc[0]["Model"]
best_model = fitted[best_name]
print("\nBest model:", best_name)

# ---------------------------------------------------------------
# Step 7: Confusion matrix
# ---------------------------------------------------------------
y_pred_best = best_model.predict(X_test_scaled)
cm = confusion_matrix(y_test, y_pred_best)
plt.figure(figsize=(5, 4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
plt.title(f"Confusion Matrix - {best_name}")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.savefig("xss_confusion_matrix.png", dpi=200)

# ---------------------------------------------------------------
# Step 8: Feature importance
# ---------------------------------------------------------------
# Tree models expose feature_importances_; Logistic Regression exposes coefficients
if hasattr(best_model, "feature_importances_"):
    importances = best_model.feature_importances_
else:
    importances = np.abs(best_model.coef_).mean(axis=0)

importance_df = pd.DataFrame({
    "Feature": X.columns,
    "Importance": importances,
}).sort_values(by="Importance", ascending=False)

print("\nTop 10 features contributing to XSS detection:")
print(importance_df.head(10).to_string(index=False))

plt.figure(figsize=(7, 5))
top10 = importance_df.head(10).iloc[::-1]
plt.barh(top10["Feature"], top10["Importance"], color="steelblue")
plt.title(f"Top 10 Features - {best_name}")
plt.xlabel("Importance")
plt.tight_layout()
plt.savefig("xss_feature_importance.png", dpi=200)

# ---------------------------------------------------------------
# Step 9: Simulated XSS pattern demo (harmless textbook test strings
# mapped to the model's most important features)
# ---------------------------------------------------------------
def generate_simulated_patterns(importance_df):
    top_features = importance_df["Feature"].head(5).tolist()
    print("\nTop 5 features contributing to the attack patterns:")
    print(top_features)
    simulated = []

    if "url_tag_script" in top_features or "html_tag_script" in top_features:
        simulated.append("<script>alert('Simulated XSS');</script>")
    if "html_tag_img" in top_features:
        simulated.append("<img src=x onerror=alert('Simulated XSS')>")
    if "js_method_eval" in top_features:
        simulated.append("eval('alert(\"Simulated XSS\")')")
    if "html_event_onload" in top_features:
        simulated.append("<div onload=alert('Simulated XSS')>Test</div>")
    if "js_method_alert" in top_features:
        simulated.append("alert('Simulated XSS')")

    print("\nGenerated simulated XSS patterns:")
    if simulated:
        for s in simulated:
            print(s)
    else:
        print("(none of the demo patterns map to the current top 5 features)")

generate_simulated_patterns(importance_df)

# ---------------------------------------------------------------
# Step 10: Save model and scaler
# ---------------------------------------------------------------
joblib.dump({"model": best_model, "scaler": scaler, "features": list(X.columns)},
            "xss_detector.joblib")
print("\nSaved xss_detector.joblib, xss_confusion_matrix.png, xss_feature_importance.png")

# Show both charts at the end so all the text output above finishes first
plt.show()
