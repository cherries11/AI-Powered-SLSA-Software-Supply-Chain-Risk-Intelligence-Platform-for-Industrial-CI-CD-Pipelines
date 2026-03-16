import pandas as pd
from sklearn.model_selection import train_test_split

# Load your training data
df = pd.read_csv('training_data.csv')
print(f"Total examples: {len(df)}")

# Separate features (X) and labels (y)
X = df.drop('label', axis=1)
y = df['label']

# First split: 70% train, 30% temporary
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, 
    test_size=0.3,
    random_state=42,
    stratify=y
)

# Second split: Split temp into 50% validation, 50% test (15% each of total)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp,
    test_size=0.5,
    random_state=42,
    stratify=y_temp
)

# Combine features and labels back
train_df = X_train.copy()
train_df['label'] = y_train

val_df = X_val.copy()
val_df['label'] = y_val

test_df = X_test.copy()
test_df['label'] = y_test

# Save to files
train_df.to_csv('train_data.csv', index=False)
val_df.to_csv('val_data.csv', index=False)
test_df.to_csv('test_data.csv', index=False)

print("\n✅ FILES CREATED:")
print(f"  train_data.csv: {len(train_df)} examples")
print(f"  val_data.csv: {len(val_df)} examples")
print(f"  test_data.csv: {len(test_df)} examples")

print("\n📊 CLASS DISTRIBUTION:")
print("\nTraining set:")
print(train_df['label'].value_counts())
print("\nValidation set:")
print(val_df['label'].value_counts())
print("\nTest set:")
print(test_df['label'].value_counts())