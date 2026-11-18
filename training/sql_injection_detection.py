# -*- coding: utf-8 -*-
"""
SQL Injection Detection
Dataset: Modified_SQL_Dataset.csv (columns: Query, Label)
Run locally: python sql_injection_detection.py
Keep Modified_SQL_Dataset.csv in the same folder as this script.
"""

import time

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from xgboost import XGBClassifier
from sklearn.metrics import (classification_report, accuracy_score,
                             f1_score, confusion_matrix)

FILE_PATH = "Modified_SQL_Dataset.csv"

# ---------------------------------------------------------------
# Step 1: Load and inspect
# ---------------------------------------------------------------
df = pd.read_csv(FILE_PATH, encoding="utf-8")
print("Shape:", df.shape)
print(df.dtypes)
print("\nLabel distribution:")
print(df["Label"].value_counts())
print("\nFirst 10 rows:")
print(df.head(10).to_string())

# ---------------------------------------------------------------
# Step 2: Clean and split
# ---------------------------------------------------------------
df = df.dropna(subset=["Query", "Label"]).copy()
df["Query"] = df["Query"].astype(str).str.strip()
before = len(df)
df = df.drop_duplicates(subset=["Query"])  # prevents train/test leakage
print(f"\nRemoved {before - len(df)} duplicate queries, {len(df)} remain")

X = df["Query"]
y = df["Label"].astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print("\nTrain class counts:\n", y_train.value_counts())
print("\nTest class counts:\n", y_test.value_counts())

# ---------------------------------------------------------------
# Step 3: Features and models
# ---------------------------------------------------------------
def make_vec(max_features=50000):
    return TfidfVectorizer(analyzer="char", ngram_range=(2, 5),
                           lowercase=True, sublinear_tf=True,
                           max_features=max_features)

# Gradient Boosting is slow on very wide sparse input, so it gets a smaller vocabulary
GB_MAX_FEATURES = 5000

models = {
    "Logistic Regression": LogisticRegression(max_iter=1000, class_weight="balanced"),
    "Random Forest": RandomForestClassifier(n_estimators=200, n_jobs=-1,
                                            class_weight="balanced", random_state=42),
    "Gradient Boosting": GradientBoostingClassifier(n_estimators=150, max_depth=4,
                                                    random_state=42),
    "XGBoost": XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                             eval_metric="logloss", n_jobs=-1, random_state=42),
}

results, fitted = [], {}
for name, clf in models.items():
    t0 = time.time()
    vec = make_vec(GB_MAX_FEATURES) if name == "Gradient Boosting" else make_vec()
    pipe = make_pipeline(vec, clf)
    pipe.fit(X_train, y_train)
    pred = pipe.predict(X_test)
    acc = accuracy_score(y_test, pred)
    f1 = f1_score(y_test, pred, average="weighted")
    results.append((name, acc, f1))
    fitted[name] = pipe
    print(f"\n=== {name} ({time.time() - t0:.1f}s) ===")
    print("Accuracy:", round(acc, 4), "| F1:", round(f1, 4))
    print(classification_report(y_test, pred, digits=4))

res_df = pd.DataFrame(results, columns=["Model", "Accuracy", "F1"]).sort_values("F1", ascending=False)
print("\nModel comparison:")
print(res_df.to_string(index=False))
best_name = res_df.iloc[0]["Model"]
best_pipe = fitted[best_name]
print("\nBest model:", best_name)

# ---------------------------------------------------------------
# Step 4: Confusion matrix
# ---------------------------------------------------------------
pred = best_pipe.predict(X_test)
cm = confusion_matrix(y_test, pred)
plt.figure(figsize=(5, 4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
plt.title(f"Confusion Matrix - {best_name}")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.savefig("confusion_matrix.png", dpi=200)
plt.show()

# ---------------------------------------------------------------
# Step 5: Patterns driving detection
# ---------------------------------------------------------------
vec = best_pipe.steps[0][1]
clf = best_pipe.steps[-1][1]
names = np.array(vec.get_feature_names_out())

if hasattr(clf, "coef_"):
    imp = clf.coef_.ravel()
    print("\nTop patterns -> malicious (Label=1):", list(names[np.argsort(imp)[-15:][::-1]]))
    print("Top patterns -> benign (Label=0):", list(names[np.argsort(imp)[:15]]))
else:
    imp = clf.feature_importances_
    top = pd.DataFrame({"Pattern": names, "Importance": imp}).sort_values("Importance", ascending=False)
    print("\nTop patterns by importance:")
    print(top.head(20).to_string(index=False))

# ---------------------------------------------------------------
# Step 6: Error analysis, quick test, save model
# ---------------------------------------------------------------
test_df = pd.DataFrame({"Query": X_test.values, "Actual": y_test.values, "Pred": pred})
errors = test_df[test_df.Actual != test_df.Pred]
print("\nMisclassified:", len(errors))
print(errors.head(10).to_string())

samples = ["SELECT * FROM users WHERE id = 5",
           "admin' OR '1'='1' --",
           "1; DROP TABLE users;--"]
print("\nSample predictions:", dict(zip(samples, best_pipe.predict(samples))))

joblib.dump(best_pipe, "sqli_detector.joblib")
print("Model saved to sqli_detector.joblib")
