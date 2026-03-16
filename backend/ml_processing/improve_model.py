# ============================================
# STEP 3.2: IMPROVING THE MODEL (FIXED VERSION)
# ============================================

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import matplotlib.pyplot as plt

print("=" * 60)
print("STEP 3.2: IMPROVING THE MODEL")
print("=" * 60)

# Load data
train_df = pd.read_csv('train_data.csv')
val_df = pd.read_csv('val_data.csv')
test_df = pd.read_csv('test_data.csv')

feature_columns = [
    'total_dependencies', 'direct_dependencies', 'outdated_count',
    'critical_count', 'high_count', 'medium_count', 'low_count', 'total_vulns'
]

X_train = train_df[feature_columns]
y_train = train_df['label']
X_val = val_df[feature_columns]
y_val = val_df['label']
X_test = test_df[feature_columns]
y_test = test_df['label']

# ============================================
# ORIGINAL MODEL (BASELINE)
# ============================================
print("\n📊 Baseline original model...")

original_model = IsolationForest(
    n_estimators=100,
    contamination=0.15,
    random_state=42
)
original_model.fit(X_train)

original_val_pred = original_model.predict(X_val)
original_val_acc = (original_val_pred == y_val).mean()
print(f"  Original model validation accuracy: {original_val_acc:.2%}")

# ============================================
# APPROACH 1: SCALE THE FEATURES
# ============================================
print("\n🔄 Approach 1: Scaling features...")

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

model_scaled = IsolationForest(
    n_estimators=200,
    contamination=0.15,
    random_state=42
)
model_scaled.fit(X_train_scaled)

val_pred_scaled = model_scaled.predict(X_val_scaled)
val_acc_scaled = (val_pred_scaled == y_val).mean()
print(f"  Scaled model validation accuracy: {val_acc_scaled:.2%}")

# ============================================
# APPROACH 2: DIFFERENT FEATURE SET
# ============================================
print("\n🔄 Approach 2: Using different features...")

# Create ratio features on copies to avoid warnings
train_enhanced = train_df.copy()
val_enhanced = val_df.copy()
test_enhanced = test_df.copy()

train_enhanced['vuln_density'] = train_enhanced['total_vulns'] / (train_enhanced['total_dependencies'] + 1)
train_enhanced['critical_ratio'] = train_enhanced['critical_count'] / (train_enhanced['total_vulns'] + 1)
train_enhanced['outdated_ratio'] = train_enhanced['outdated_count'] / (train_enhanced['total_dependencies'] + 1)

val_enhanced['vuln_density'] = val_enhanced['total_vulns'] / (val_enhanced['total_dependencies'] + 1)
val_enhanced['critical_ratio'] = val_enhanced['critical_count'] / (val_enhanced['total_vulns'] + 1)
val_enhanced['outdated_ratio'] = val_enhanced['outdated_count'] / (val_enhanced['total_dependencies'] + 1)

test_enhanced['vuln_density'] = test_enhanced['total_vulns'] / (test_enhanced['total_dependencies'] + 1)
test_enhanced['critical_ratio'] = test_enhanced['critical_count'] / (test_enhanced['total_vulns'] + 1)
test_enhanced['outdated_ratio'] = test_enhanced['outdated_count'] / (test_enhanced['total_dependencies'] + 1)

# New feature set
enhanced_features = feature_columns + ['vuln_density', 'critical_ratio', 'outdated_ratio']

X_train_enhanced = train_enhanced[enhanced_features]
X_val_enhanced = val_enhanced[enhanced_features]
X_test_enhanced = test_enhanced[enhanced_features]

model_enhanced = IsolationForest(
    n_estimators=200,
    contamination=0.15,
    random_state=42
)
model_enhanced.fit(X_train_enhanced)

val_pred_enhanced = model_enhanced.predict(X_val_enhanced)
val_acc_enhanced = (val_pred_enhanced == y_val).mean()
print(f"  Enhanced features validation accuracy: {val_acc_enhanced:.2%}")

# ============================================
# APPROACH 3: ADJUST DECISION THRESHOLD (using best model so far)
# ============================================
print("\n🔄 Approach 3: Adjusting decision threshold...")

# Use original model for threshold tuning
scores = original_model.decision_function(X_val)
thresholds = [-0.017, -0.002, 0.013, 0.022, 0.030]  # Your tested thresholds

best_threshold = 0
best_threshold_acc = 0

for thresh in thresholds:
    pred = np.where(scores < thresh, -1, 1)
    acc = (pred == y_val).mean()
    print(f"  Threshold {thresh:.3f}: accuracy {acc:.2%}")
    
    if acc > best_threshold_acc:
        best_threshold_acc = acc
        best_threshold = thresh

print(f"\n✅ Best threshold: {best_threshold:.3f} (accuracy: {best_threshold_acc:.2%})")

# ============================================
# CHOOSE BEST APPROACH
# ============================================
print("\n" + "=" * 60)
print("📊 RESULTS COMPARISON")
print("=" * 60)

results = {
    "Original model": original_val_acc,
    "Scaled features": val_acc_scaled,
    "Enhanced features": val_acc_enhanced,
    "Adjusted threshold": best_threshold_acc
}

for name, acc in results.items():
    print(f"  {name}: {acc:.2%}")

best_approach = max(results, key=results.get)
best_accuracy = results[best_approach]

print(f"\n✅ Best approach: {best_approach} with {best_accuracy:.2%} accuracy")

# ============================================
# TRAIN FINAL MODEL WITH BEST APPROACH
# ============================================
print("\n🎯 Training final model...")

if best_approach == "Scaled features":
    final_model = model_scaled
    final_scaler = scaler
    joblib.dump(final_scaler, 'scaler.pkl')
    print("  Scaler saved to scaler.pkl")
    # Test on test set
    X_test_final = scaler.transform(X_test)
    
elif best_approach == "Enhanced features":
    final_model = model_enhanced
    # Save feature list
    with open('enhanced_features.txt', 'w') as f:
        for feat in enhanced_features:
            f.write(feat + '\n')
    print("  Enhanced features list saved")
    X_test_final = test_enhanced[enhanced_features]
    
elif best_approach == "Adjusted threshold":
    final_model = original_model
    # Save threshold
    with open('threshold.txt', 'w') as f:
        f.write(str(best_threshold))
    print(f"  Threshold {best_threshold} saved to threshold.txt")
    X_test_final = X_test
    
else:  # Original model
    final_model = original_model
    X_test_final = X_test

# Save final model
joblib.dump(final_model, 'final_anomaly_detector.pkl')
print(f"  Final model saved to final_anomaly_detector.pkl")

# Test on test set
test_pred = final_model.predict(X_test_final)
test_acc = (test_pred == y_test).mean()

print(f"\n📊 FINAL TEST ACCURACY: {test_acc:.2%}")

print("\n📈 Final Classification Report:")
print(classification_report(y_test, test_pred, 
                          target_names=['Normal (1)', 'Anomaly (-1)']))

# Confusion Matrix
cm_test = confusion_matrix(y_test, test_pred)
print("\n  Final Confusion Matrix:")
print(f"               Predicted")
print(f"               Normal  Anomaly")
print(f"  Actual Normal   {cm_test[0,0]:5d}   {cm_test[0,1]:5d}")
print(f"         Anomaly   {cm_test[1,0]:5d}   {cm_test[1,1]:5d}")

# ============================================
# SAVE IMPROVED MODEL SUMMARY
# ============================================
print("\n" + "=" * 60)
print("✅ STEP 3.2 COMPLETE!")
print("=" * 60)
print(f"""
📊 IMPROVED MODEL SUMMARY:
--------------------------
Best approach:     {best_approach}
Validation accuracy: {best_accuracy:.2%}
Test accuracy:       {test_acc:.2%}

Files created:
  - final_anomaly_detector.pkl  (improved model)
  - {'scaler.pkl' if best_approach == 'Scaled features' else 'threshold.txt'}

Next: Step 3.3 - Integrate into scanner!
""")