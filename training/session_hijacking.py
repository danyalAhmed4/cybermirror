# -*- coding: utf-8 -*-
"""
Session Hijacking Detection
Dataset: SessionHijacking.csv (made by generate_session_hijacking_dataset.py)
Run locally: python session_hijacking_detection.py
Keep SessionHijacking.csv (or the .csv.gz) in the same folder as this script.

Two tasks on the same features:
  Binary     : Normal vs Hijacked
  Multiclass : Normal / Cookie_Replay / Sidejacking / Session_Fixation /
               MITM_Hijack / Session_Prediction

Gradient boosting uses scikit-learn's HistGradientBoostingClassifier, which is
the same algorithm family as GradientBoostingClassifier but far faster on
80k rows (histogram binning + multithreading).
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
RANDOM_STATE = 42
TUNE = True                # grid search for Random Forest / Gradient Boosting
TUNE_SAMPLE = 10000        # rows used for grid search (keeps tuning fast)
USE_SMOTE = True           # balance the TRAINING set only (set False for a faster run)

GB_NAME = "Gradient Boosting (Hist)"

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
# Step 2: Preprocessing
# Identifiers (IPs, session id, timestamp, log text) are dropped so models
# learn behaviour instead of memorising rows.
# ---------------------------------------------------------------
data = data.replace([float("inf"), float("-inf")], np.nan)
data = data.fillna(data.mean(numeric_only=True))

DROP = ["Flow ID", "Timestamp", "Source IP", "Destination IP", "Session ID", "User ID",
        "Source Port", "logs", "Label", "Binary Label", "User Agent", "Endpoint", "HTTP Method"]
X = data.drop(columns=[c for c in DROP if c in data.columns]).select_dtypes("number").copy()
X["UA_Is_Script"] = data["User Agent"].str.contains("python|curl|Go-http|Burp", case=False).astype(int)
X["Is_Write_Method"] = data["HTTP Method"].isin(["POST", "PUT", "DELETE"]).astype(int)
print(f"\n{X.shape[1]} features used")

label_enc = LabelEncoder().fit(data["Label"])
y_multi = label_enc.transform(data["Label"])
y_binary = (data["Label"] != "Normal").astype(int).values

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

    # Split first, then SMOTE on the TRAINING set only
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
    res_df.to_csv(f"{prefix}_model_comparison.csv", index=False)

    best_name = res_df.iloc[0]["Model"]
    best_model = fitted[best_name]
    print("\nBest model:", best_name)

    # ---------------- Confusion matrix ----------------
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
    plt.savefig(f"{prefix}_confusion_matrix.png", dpi=200)

    # ---------------- Feature importance ----------------
    # Logistic Regression and HistGradientBoosting have no feature_importances_,
    # so fall back to Random Forest importances if one of them wins.
    if hasattr(best_model, "feature_importances_"):
        imp_model, imp_name = best_model, best_name
    else:
        imp_model, imp_name = fitted["Random Forest"], "Random Forest"
    importance_df = pd.DataFrame({
        "Feature": X.columns,
        "Importance": imp_model.feature_importances_,
    }).sort_values(by="Importance", ascending=False)

    print(f"\nTop 10 features contributing to session hijacking detection "
          f"({task_name}, importances from {imp_name}):")
    print(importance_df.head(10).to_string(index=False))

    plt.figure(figsize=(7, 5))
    top10 = importance_df.head(10).iloc[::-1]
    plt.barh(top10["Feature"], top10["Importance"], color="steelblue")
    plt.title(f"Top 10 Features - {task_name} ({imp_name})")
    plt.xlabel("Importance")
    plt.tight_layout()
    plt.savefig(f"{prefix}_feature_importance.png", dpi=200)

    # ---------------- Save model ----------------
    joblib.dump({"model": best_model, "scaler": scaler, "features": list(X.columns),
                 "classes": target_names},
                f"{prefix}_detector.joblib")
    print(f"Saved {prefix}_detector.joblib, {prefix}_confusion_matrix.png, {prefix}_feature_importance.png")
    return res_df


# ---------------------------------------------------------------
# Step 4: Run both tasks
# ---------------------------------------------------------------
res_binary = run_task("Binary", y_binary, "session_binary")
res_multi = run_task("Multiclass", y_multi, "session_multiclass")

print("\n" + "=" * 60)
print("FINAL SUMMARY")
print("=" * 60)
print("\nBinary (Normal vs Hijacked):\n", res_binary.to_string(index=False))
print("\nMulticlass (6 classes):\n", res_multi.to_string(index=False))

# Show charts at the end so all the text output above finishes first
plt.show()
