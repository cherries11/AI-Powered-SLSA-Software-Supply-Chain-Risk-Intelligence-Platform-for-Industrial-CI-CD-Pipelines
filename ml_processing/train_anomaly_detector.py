# ============================================
# STEP 3.1: TRAIN ANOMALY DETECTOR
# ============================================

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

print("=" * 60)
print("STEP 3.1: TRAINING ANOMALY DETECTOR")
print("=" * 60)

# ============================================
# STEP 1: LOAD THE DATA
# ============================================
print("\n📊 Loading datasets...")

train_df = pd.read_csv('train_data.csv')
val_df = pd.read_csv('val_data.csv')
test_df = pd.read_csv('test_data.csv')

print(f"  Train set: {len(train_df)} examples")
print(f"  Validation set: {len(val_df)} examples")
print(f"  Test set: {len(test_df)} examples")

# ============================================
# STEP 2: PREPARE FEATURES AND LABELS
# ============================================
print("\n🔧 Preparing features...")

# Features to use for training
feature_columns = [
    'total_dependencies',
    'direct_dependencies',
    'outdated_count',
    'critical_count',
    'high_count',
    'medium_count',
    'low_count',
    'total_vulns'
]

# Split features (X) and labels (y)
X_train = train_df[feature_columns]
y_train = train_df['label']

X_val = val_df[feature_columns]
y_val = val_df['label']

X_test = test_df[feature_columns]
y_test = test_df['label']

print(f"  Using {len(feature_columns)} features: {feature_columns}")
print(f"  Train shape: {X_train.shape}")
print(f"  Validation shape: {X_val.shape}")
print(f"  Test shape: {X_test.shape}")

# ============================================
# STEP 3: TRAIN ISOLATION FOREST
# ============================================
print("\n🤖 Training Isolation Forest model...")

# Create the model
model = IsolationForest(
    n_estimators=100,        # Number of trees
    max_samples='auto',       # Samples per tree
    contamination=0.15,       # Expected % of anomalies (adjust based on your data)
    random_state=42,          # For reproducible results
    bootstrap=False
)

# Train the model
model.fit(X_train)

print("  ✅ Model training complete!")

# ============================================
# STEP 4: PREDICT ON TRAIN SET
# ============================================
print("\n📈 Evaluating on TRAIN set...")

# Predict (-1 = anomaly, 1 = normal)
train_pred = model.predict(X_train)

# Convert predictions to match our labels (-1 = anomaly, 1 = normal)
train_accuracy = accuracy_score(y_train, train_pred)
print(f"  Train accuracy: {train_accuracy:.2%}")

# ============================================
# STEP 5: PREDICT ON VALIDATION SET
# ============================================
print("\n📈 Evaluating on VALIDATION set...")

val_pred = model.predict(X_val)
val_accuracy = accuracy_score(y_val, val_pred)
print(f"  Validation accuracy: {val_accuracy:.2%}")

# Detailed validation report
print("\n  Validation Classification Report:")
print(classification_report(y_val, val_pred, 
                          target_names=['Normal (1)', 'Anomaly (-1)']))

# Confusion Matrix
cm = confusion_matrix(y_val, val_pred)
print("\n  Confusion Matrix:")
print(f"               Predicted")
print(f"               Normal  Anomaly")
print(f"  Actual Normal   {cm[0,0]:5d}   {cm[0,1]:5d}")
print(f"         Anomaly   {cm[1,0]:5d}   {cm[1,1]:5d}")

# ============================================
# STEP 6: TRY DIFFERENT CONTAMINATION VALUES
# ============================================
print("\n🔄 Tuning contamination parameter...")

contamination_values = [0.1, 0.12, 0.15, 0.18, 0.2, 0.25]
best_accuracy = 0
best_contamination = 0.15
best_model = None

for cont in contamination_values:
    # Train with different contamination
    test_model = IsolationForest(
        n_estimators=100,
        contamination=cont,
        random_state=42
    )
    test_model.fit(X_train)
    
    # Predict on validation
    pred = test_model.predict(X_val)
    acc = accuracy_score(y_val, pred)
    
    print(f"  contamination={cont}: validation accuracy = {acc:.2%}")
    
    if acc > best_accuracy:
        best_accuracy = acc
        best_contamination = cont
        best_model = test_model

print(f"\n✅ Best contamination: {best_contamination} (accuracy: {best_accuracy:.2%})")

# ============================================
# STEP 7: FINAL TEST ON TEST SET
# ============================================
print("\n🎯 FINAL EVALUATION ON TEST SET (model has NEVER seen this data!)")

test_pred = best_model.predict(X_test)
test_accuracy = accuracy_score(y_test, test_pred)
print(f"\n  Test accuracy: {test_accuracy:.2%}")

print("\n  Test Classification Report:")
print(classification_report(y_test, test_pred, 
                          target_names=['Normal (1)', 'Anomaly (-1)']))

# Final confusion matrix
cm_test = confusion_matrix(y_test, test_pred)
print("\n  Test Confusion Matrix:")
print(f"               Predicted")
print(f"               Normal  Anomaly")
print(f"  Actual Normal   {cm_test[0,0]:5d}   {cm_test[0,1]:5d}")
print(f"         Anomaly   {cm_test[1,0]:5d}   {cm_test[1,1]:5d}")

# ============================================
# STEP 8: SAVE THE BEST MODEL
# ============================================
print("\n💾 Saving best model...")

model_filename = 'anomaly_detector.pkl'
joblib.dump(best_model, model_filename)
print(f"  ✅ Model saved to {model_filename}")

# Also save feature names for later use
feature_names = feature_columns
with open('feature_names.txt', 'w') as f:
    for feat in feature_names:
        f.write(feat + '\n')
print(f"  ✅ Feature names saved to feature_names.txt")

# ============================================
# STEP 9: VISUALIZE RESULTS
# ============================================
print("\n📊 Creating visualizations...")

fig, axes = plt.subplots(2, 2, figsize=(12, 10))

# Plot 1: Confusion Matrix
sns.heatmap(cm_test, annot=True, fmt='d', cmap='Blues', 
            xticklabels=['Normal', 'Anomaly'],
            yticklabels=['Normal', 'Anomaly'],
            ax=axes[0,0])
axes[0,0].set_title('Test Set Confusion Matrix')
axes[0,0].set_xlabel('Predicted')
axes[0,0].set_ylabel('Actual')

# Plot 2: Feature Importance (Isolation Forest doesn't have built-in importance)
# We'll show feature distributions instead
for i, feat in enumerate(feature_columns[:4]):  # First 4 features
    if i < 4:
        row, col = i//2, i%2
        axes[1, row].hist([train_df[train_df['label']==1][feat], 
                           train_df[train_df['label']==-1][feat]], 
                          label=['Normal', 'Anomaly'], alpha=0.7, bins=20)
        axes[1, row].set_xlabel(feat)
        axes[1, row].set_ylabel('Count')
        axes[1, row].set_title(f'{feat} Distribution')
        axes[1, row].legend()

plt.tight_layout()
plt.savefig('model_results.png', dpi=150)
print("  ✅ Visualization saved to model_results.png")

# ============================================
# STEP 10: SUMMARY
# ============================================
print("\n" + "=" * 60)
print("✅ STEP 3.1 COMPLETE!")
print("=" * 60)
print(f"""
📊 MODEL SUMMARY:
-----------------
Training examples:     {len(X_train)}
Validation examples:   {len(X_val)}
Test examples:         {len(X_test)}
Features used:         {len(feature_columns)}

Best contamination:    {best_contamination}
Validation accuracy:   {best_accuracy:.2%}
Test accuracy:         {test_accuracy:.2%}

Files created:
  - anomaly_detector.pkl    (trained model)
  - feature_names.txt       (feature list)
  - model_results.png       (visualizations)

Next: Step 3.2 - Integrate model into scanner!
""")