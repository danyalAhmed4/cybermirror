# -*- coding: utf-8 -*-
"""
Session Hijacking Detection — APP FEATURE SET
Copied from session_hijacking.py with ONLY the feature selection changed.

Keep (application-observable):
  IP Changes In Session, User Agent Changed, Concurrent Sessions Same Token,
  Token Entropy, Cookie Reuse Count, Is HTTPS, Secure Cookie Flag, SID In URL,
  SID Unchanged After Login, SIDs Tried Per Min, Failed Auth Count,
  Error Response (4xx), Requests Per Min, Time Since Last Request,
  Login To Request Gap, Referer Missing, Sensitive Endpoint Hit,
  Session Age Sec, UA_Is_Script, Is_Write_Method

Drop: TLS Fingerprint Match, TTL Delta, Gateway MAC Changed, all flow/packet/
flag columns, Geo Distance Km, ports, Flow Duration.
"""

import os
import time

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from imblearn.over_sampling import SMOTE
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (classification_report, accuracy_score,
                             f1_score, confusion_matrix)
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder
from xgboost import XGBClassifier

FILE_PATH = "SessionHijacking.csv" if os.path.exists("SessionHijacking.csv") else "SessionHijacking.csv.gz"
# Optional OrbitMart-live rows from export_live_session_features.py (appended)
LIVE_FILE = os.getenv(
    "LIVE_SESSION_CSV",
    "live_session_features.csv" if os.path.exists("live_session_features.csv") else "",
)
LIVE_REPEAT = int(os.getenv("LIVE_SESSION_REPEAT", "40"))  # upweight scarce live rows
RANDOM_STATE = 42
TUNE = True
TUNE_SAMPLE = 10000
USE_SMOTE = True

GB_NAME = "Gradient Boosting (Hist)"

KEEP_FEATURES = [
    "IP Changes In Session",
    "User Agent Changed",
    "Concurrent Sessions Same Token",
    "Token Entropy",
    "Cookie Reuse Count",
    "Is HTTPS",
    "Secure Cookie Flag",
    "SID In URL",
    "SID Unchanged After Login",
    "SIDs Tried Per Min",
    "Failed Auth Count",
    "Error Response (4xx)",
    "Requests Per Min",
    "Time Since Last Request",
    "Login To Request Gap",
    "Referer Missing",
    "Sensitive Endpoint Hit",
    "Session Age Sec",
    # derived below (same as original script)
    "UA_Is_Script",
    "Is_Write_Method",
]

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODELS_DIR = os.path.join(_ROOT, "models")
RESULTS_DIR = os.path.join(_ROOT, "results")
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# ---------------------------------------------------------------
# Step 1: Load dataset
# ---------------------------------------------------------------
data = pd.read_csv(FILE_PATH)
data.columns = data.columns.str.strip()
print("Shape:", data.shape)
print("\nLabel distribution:")
print(data["Label"].value_counts())
print("\nFirst 5 rows:")
print(data.head().to_string())

# ---------------------------------------------------------------
# Step 2: Preprocessing — APP FEATURE SELECTION ONLY CHANGE
# ---------------------------------------------------------------
data = data.replace([float("inf"), float("-inf")], np.nan)
data = data.fillna(data.mean(numeric_only=True))

X = pd.DataFrame(index=data.index)
for col in KEEP_FEATURES:
    if col == "UA_Is_Script":
        X[col] = data["User Agent"].astype(str).str.contains(
            "python|curl|Go-http|Burp", case=False
        ).astype(int)
    elif col == "Is_Write_Method":
        X[col] = data["HTTP Method"].isin(["POST", "PUT", "DELETE"]).astype(int)
    elif col in data.columns:
        X[col] = data[col]
    else:
        raise KeyError(f"Required feature missing from dataset: {col}")

print(f"\n{X.shape[1]} app features used:")
print(list(X.columns))

# Mix in live OrbitMart session vectors when present (train ≈ runtime)
if LIVE_FILE and os.path.isfile(LIVE_FILE):
    live = pd.read_csv(LIVE_FILE)
    live.columns = live.columns.str.strip()
    if "Label" in live.columns:
        live_X = pd.DataFrame(index=live.index)
        for col in KEEP_FEATURES:
            if col in live.columns:
                live_X[col] = live[col]
            else:
                live_X[col] = 0.0
        reps = max(LIVE_REPEAT, 1)
        X = pd.concat([X] + [live_X] * reps, ignore_index=True)
        live_labels = pd.concat([live["Label"]] * reps, ignore_index=True)
        data_labels = pd.concat(
            [data["Label"].reset_index(drop=True), live_labels], ignore_index=True
        )
        print(
            f"\nMerged live sessions: {len(live)} unique × {reps} = "
            f"{len(live) * reps} rows from {LIVE_FILE}"
        )
    else:
        data_labels = data["Label"].reset_index(drop=True)
else:
    data_labels = data["Label"].reset_index(drop=True)

label_enc = LabelEncoder().fit(data_labels)
y_multi = label_enc.transform(data_labels)
y_binary = (data_labels != "Normal").astype(int).values

# ---------------------------------------------------------------
# Step 3: Models and hyperparameter grids
# ---------------------------------------------------------------
def make_models(n_classes):
    xgb_metric = "logloss" if n_classes == 2 else "mlogloss"
    return {
        "Logistic Regression": LogisticRegression(max_iter=2000, random_state=RANDOM_STATE),
        "Random Forest": RandomForestClassifier(random_state=RANDOM_STATE, n_jobs=-1),
        GB_NAME: HistGradientBoostingClassifier(early_stopping=False, random_state=RANDOM_STATE),
        "XGBoost": XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                                 tree_method="hist", eval_metric=xgb_metric,
                                 random_state=RANDOM_STATE, n_jobs=-1),
    }

param_grids = {
    "Random Forest": {
        "n_estimators": [100, 200],
        "max_depth": [10, 15, None],
    },
    GB_NAME: {
        "max_iter": [100, 200],
        "max_depth": [3, 6],
        "learning_rate": [0.05, 0.1],
    },
}


def run_task(task_name, y, prefix):
    print("\n" + "=" * 60)
    print(f"TASK: {task_name}")
    print("=" * 60)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y)
    print("Train distribution before SMOTE:\n", pd.Series(y_train).value_counts().sort_index())

    if USE_SMOTE:
        X_train, y_train = SMOTE(random_state=RANDOM_STATE).fit_resample(X_train, y_train)
        print("Train distribution after SMOTE:\n", pd.Series(y_train).value_counts().sort_index())

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)
    y_train = np.asarray(y_train)
    y_test = np.asarray(y_test)

    rng = np.random.RandomState(RANDOM_STATE)
    tune_idx = rng.choice(len(X_train_s), size=min(TUNE_SAMPLE, len(X_train_s)), replace=False)

    target_names = list(label_enc.classes_) if task_name == "Multiclass" else ["Normal", "Hijacked"]
    n_classes = len(target_names)

    results, fitted = [], {}
    for model_name, model in make_models(n_classes).items():
        t0 = time.time()

        if TUNE and model_name in param_grids:
            grid = GridSearchCV(model, param_grids[model_name], cv=3, n_jobs=-1, verbose=1)
            grid.fit(X_train_s[tune_idx], y_train[tune_idx])
            print(f"\n{model_name} best params: {grid.best_params_}")
            model = clone(model).set_params(**grid.best_params_)

        model.fit(X_train_s, y_train)
        y_pred = model.predict(X_test_s)

        acc = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average="weighted")
        results.append((model_name, acc, f1))
        fitted[model_name] = model

        print(f"\n=== Results for {model_name} ({time.time() - t0:.1f}s) ===")
        print("Accuracy:", round(acc, 4))
        print("F1 Score:", round(f1, 4))
        print("Classification Report:\n",
              classification_report(y_test, y_pred, target_names=target_names, digits=4))
        print("-" * 40)

    res_df = pd.DataFrame(results, columns=["Model", "Accuracy", "F1"]).sort_values("F1", ascending=False)
    print(f"\nModel comparison ({task_name}):")
    print(res_df.to_string(index=False))
    res_df.to_csv(os.path.join(RESULTS_DIR, f"{prefix}_model_comparison.csv"), index=False)

    best_name = res_df.iloc[0]["Model"]
    best_model = fitted[best_name]
    print("\nBest model:", best_name)

    y_pred_best = best_model.predict(X_test_s)
    cm = confusion_matrix(y_test, y_pred_best)
    plt.figure(figsize=(7, 6) if task_name == "Multiclass" else (5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=target_names, yticklabels=target_names)
    plt.title(f"Confusion Matrix - {best_name} ({task_name})")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, f"{prefix}_confusion_matrix.png"), dpi=200)

    if hasattr(best_model, "feature_importances_"):
        imp_model, imp_name = best_model, best_name
    else:
        imp_model, imp_name = fitted["Random Forest"], "Random Forest"
    importance_df = pd.DataFrame({
        "Feature": X.columns,
        "Importance": imp_model.feature_importances_,
    }).sort_values(by="Importance", ascending=False)

    print(f"\nTop 10 features ({task_name}, from {imp_name}):")
    print(importance_df.head(10).to_string(index=False))

    plt.figure(figsize=(7, 5))
    top10 = importance_df.head(10).iloc[::-1]
    plt.barh(top10["Feature"], top10["Importance"], color="steelblue")
    plt.title(f"Top 10 Features - {task_name} ({imp_name})")
    plt.xlabel("Importance")
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, f"{prefix}_feature_importance.png"), dpi=200)

    out_path = os.path.join(MODELS_DIR, f"{prefix}_detector.joblib")
    joblib.dump({"model": best_model, "scaler": scaler, "features": list(X.columns),
                 "classes": target_names},
                out_path)
    print(f"Saved {out_path}")
    return res_df


res_binary = run_task("Binary", y_binary, "session_app_binary")
res_multi = run_task("Multiclass", y_multi, "session_app_multiclass")

print("\n" + "=" * 60)
print("FINAL SUMMARY (APP FEATURES)")
print("=" * 60)
print("\nBinary:\n", res_binary.to_string(index=False))
print("\nMulticlass:\n", res_multi.to_string(index=False))

# Old vs new comparison table
def _best_row(csv_path):
    df = pd.read_csv(csv_path)
    return df.sort_values("F1", ascending=False).iloc[0]


old_bin = _best_row(os.path.join(os.path.dirname(__file__), "session_binary_model_comparison.csv"))
old_multi = _best_row(os.path.join(os.path.dirname(__file__), "session_multiclass_model_comparison.csv"))
new_bin = res_binary.iloc[0]
new_multi = res_multi.iloc[0]

cmp = pd.DataFrame([
    {
        "Task": "Binary",
        "Variant": "old_full_features",
        "BestModel": old_bin["Model"],
        "Accuracy": old_bin["Accuracy"],
        "F1": old_bin["F1"],
    },
    {
        "Task": "Binary",
        "Variant": "new_app_features",
        "BestModel": new_bin["Model"],
        "Accuracy": new_bin["Accuracy"],
        "F1": new_bin["F1"],
    },
    {
        "Task": "Multiclass",
        "Variant": "old_full_features",
        "BestModel": old_multi["Model"],
        "Accuracy": old_multi["Accuracy"],
        "F1": old_multi["F1"],
    },
    {
        "Task": "Multiclass",
        "Variant": "new_app_features",
        "BestModel": new_multi["Model"],
        "Accuracy": new_multi["Accuracy"],
        "F1": new_multi["F1"],
    },
])
cmp_path = os.path.join(RESULTS_DIR, "session_old_vs_new.csv")
cmp.to_csv(cmp_path, index=False)
print("\nOld vs new comparison:")
print(cmp.to_string(index=False))
print(f"\nWrote {cmp_path}")

# Comment on any drop:
# Dropping flow/packet/TLS/geo features removes strong network-layer signals that
# the original synthetic dataset used to separate hijack classes. App-only features
# are what CyberMirror can observe at runtime, so a modest accuracy/F1 drop is
# expected and preferable to relying on unavailable packet captures.
print(
    "\n# NOTE: Any accuracy/F1 drop vs the old models is expected: flow/packet/"
    "TLS/geo features were removed. The app-feature models match what the Flask "
    "logger can actually compute at runtime."
)
