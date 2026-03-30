# ML Model Documentation

## Model: Isolation Forest

| Parameter | Value |
|-----------|-------|
| Algorithm | Isolation Forest |
| Library | scikit-learn 1.8.0 |
| Contamination | 0.1 |
| Threshold | -0.017 |

## Training Data

| Source | Count |
|--------|-------|
| MegaVul dataset | 339,548 entries |
| Vulnerable functions | 17,380 |
| Non-vulnerable functions | 322,168 |
| Final training examples | 1,698 |

## Features (8)

1. total_dependencies
2. direct_dependencies
3. outdated_count
4. critical_count
5. high_count
6. medium_count
7. low_count
8. total_vulns

## Performance

| Metric | Score |
|--------|-------|
| Anomaly Detection Rate | 89% |
| Test Accuracy | 52-53% |

## Score Interpretation

| Score | Risk |
|-------|------|
| < -0.2 | HIGH |
| -0.2 to -0.017 | MEDIUM |
| > -0.017 | LOW |

## Files

- final_anomaly_detector.pkl
- threshold.txt
- training_data.csv