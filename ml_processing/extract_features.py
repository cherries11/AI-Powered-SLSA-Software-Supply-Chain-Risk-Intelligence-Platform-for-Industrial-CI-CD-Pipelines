import json
import csv
import os
from collections import defaultdict
import random

# ============================================
# CONFIGURATION - UPDATE THIS PATH!
# ============================================
MEGAVUL_FILE = r"C:\Users\pc\Desktop\2cs\S2\ml\AI-Powered-SLSA-Software-Supply-Chain-Risk-Intelligence-Platform-for-Industrial-CI-CD-Pipelines-main\ml_processing\megavul_simple.json"
OUTPUT_CSV = "training_data.csv"

# ============================================
# STEP 1: LOAD AND EXPLORE THE DATA
# ============================================
def load_megavul(file_path):
    """Load the MegaVul JSON file"""
    print(f"Loading MegaVul from: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print(f"Total entries: {len(data)}")
    return data

# ============================================
# STEP 2: EXTRACT SEVERITY FROM CVSS VECTOR
# ============================================
def get_severity_from_cvss(cvss_vector):
    """
    Determine severity from CVSS vector
    CVSS v2: AV:N/AC:L/Au:N/C:P/I:P/A:P
    CVSS v3: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    if not cvss_vector:
        return "MEDIUM"  # Default
    
    cvss = cvss_vector.upper()
    
    # Check for CRITICAL indicators
    if ('C:H/I:H/A:H' in cvss or  # All High
        'C:C/I:C/A:C' in cvss or  # All Complete
        'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' in cvss or  # CVSS 3.1 Critical pattern
        '9.0' in cvss or '10.0' in cvss):  # Score indicators
        return "CRITICAL"
    
    # Check for HIGH indicators
    elif ('C:H' in cvss or 'I:H' in cvss or 'A:H' in cvss or
          'HIGH' in cvss or '8.0' in cvss or '9.0' in cvss):
        return "HIGH"
    
    # Check for LOW indicators
    elif ('C:L' in cvss and 'I:L' in cvss and 'A:L' in cvss) or 'LOW' in cvss:
        return "LOW"
    
    # Default to MEDIUM
    else:
        return "MEDIUM"

# ============================================
# STEP 3: GROUP VULNERABILITIES BY PROJECT
# ============================================
def group_by_project(data):
    """Group vulnerabilities by repository/project"""
    projects = defaultdict(lambda: {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "total": 0,
        "cves": set(),
        "files": set()
    })
    
    print("\nGrouping by project...")
    
    for i, item in enumerate(data):
        if i % 50000 == 0 and i > 0:
            print(f"  Processed {i}/{len(data)} entries...")
        
        # Extract project from git_url
        git_url = item.get('git_url', '')
        if git_url and 'github.com' in git_url:
            # Extract owner/repo from URL
            # Example: https://github.com/openssl/openssl/commit/...
            parts = git_url.split('/')
            if len(parts) >= 5:
                project = f"{parts[3]}/{parts[4]}"
            else:
                project = "unknown"
        else:
            project = "unknown"
        
        # Get vulnerability info
        is_vul = item.get('is_vul', False)
        cve_id = item.get('cve_id', '')
        
        if is_vul:
            # Determine severity
            cvss = item.get('cvss_vector', '')
            severity = get_severity_from_cvss(cvss)
            
            # Count by severity
            if severity == "CRITICAL":
                projects[project]["critical"] += 1
            elif severity == "HIGH":
                projects[project]["high"] += 1
            elif severity == "MEDIUM":
                projects[project]["medium"] += 1
            elif severity == "LOW":
                projects[project]["low"] += 1
            
            projects[project]["total"] += 1
            if cve_id:
                projects[project]["cves"].add(cve_id)
        
        # Track files (for size estimation)
        file_path = item.get('file_path', '')
        if file_path:
            projects[project]["files"].add(file_path)
    
    return projects

# ============================================
# STEP 4: CREATE FEATURE VECTORS
# ============================================
def create_feature_vectors(projects):
    """Convert grouped projects to ML feature vectors"""
    features = []
    
    print("\nCreating feature vectors...")
    
    for project, counts in projects.items():
        # Skip projects with too few vulnerabilities
        if counts["total"] < 1:
            continue
        
        # Estimate project size based on files and vulns
        num_files = len(counts["files"])
        
        # Estimate total dependencies (more files = more deps)
        if num_files > 50:
            est_deps = 150 + (counts["total"] * 2)
        elif num_files > 20:
            est_deps = 80 + (counts["total"] * 2)
        elif num_files > 5:
            est_deps = 40 + (counts["total"] * 2)
        else:
            est_deps = 20 + (counts["total"] * 2)
        
        # Cap at reasonable values
        est_deps = min(est_deps, 500)
        
        # Estimate direct dependencies (usually 30-40% of total)
        direct_deps = int(est_deps * 0.35)
        
        # Estimate outdated packages (more vulns = more outdated)
        outdated_ratio = min(0.3 + (counts["total"] * 0.01), 0.8)
        outdated_count = int(est_deps * outdated_ratio)
        
        # Create feature vector
        feature = {
            "project": project,
            "total_dependencies": est_deps,
            "direct_dependencies": direct_deps,
            "outdated_count": outdated_count,
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
            "total_vulns": counts["total"],
            "num_files": num_files,
            "label": -1  # ANOMALY (vulnerable project)
        }
        
        features.append(feature)
    
    return features

# ============================================
# STEP 5: CREATE NORMAL EXAMPLES (NON-VULNERABLE)
# ============================================
def create_normal_examples(projects, num_examples=500):
    """
    Create synthetic normal examples
    Based on non-vulnerable parts of projects
    """
    normal_examples = []
    
    print(f"\nCreating {num_examples} normal examples...")
    
    for i in range(num_examples):
        # Randomly select a project as template
        if projects:
            template = random.choice(list(projects.values()))
            
            # Normal projects have few vulnerabilities
            base_size = random.randint(20, 100)
            
            normal = {
                "project": f"normal_project_{i}",
                "total_dependencies": base_size,
                "direct_dependencies": int(base_size * random.uniform(0.3, 0.4)),
                "outdated_count": random.randint(0, 5),
                "critical_count": 0,
                "high_count": random.randint(0, 1),
                "medium_count": random.randint(0, 3),
                "low_count": random.randint(0, 4),
                "total_vulns": random.randint(0, 5),
                "num_files": random.randint(10, 50),
                "label": 1  # NORMAL
            }
        else:
            # Fallback if no projects
            base_size = random.randint(20, 80)
            normal = {
                "project": f"normal_project_{i}",
                "total_dependencies": base_size,
                "direct_dependencies": int(base_size * 0.35),
                "outdated_count": random.randint(0, 3),
                "critical_count": 0,
                "high_count": 0,
                "medium_count": random.randint(0, 2),
                "low_count": random.randint(0, 2),
                "total_vulns": random.randint(0, 3),
                "num_files": random.randint(10, 40),
                "label": 1
            }
        
        normal_examples.append(normal)
    
    return normal_examples

# ============================================
# STEP 6: SAVE TO CSV
# ============================================
def save_to_csv(anomaly_features, normal_features, output_file):
    """Save features to CSV file"""
    all_features = anomaly_features + normal_features
    
    # Shuffle to mix normal and anomaly
    random.shuffle(all_features)
    
    # Define CSV columns
    fieldnames = [
        "project", "total_dependencies", "direct_dependencies",
        "outdated_count", "critical_count", "high_count",
        "medium_count", "low_count", "total_vulns",
        "num_files", "label"
    ]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_features)
    
    print(f"\n✅ Saved {len(all_features)} examples to {output_file}")
    
    # Print statistics
    anomaly_count = sum(1 for f in all_features if f["label"] == -1)
    normal_count = sum(1 for f in all_features if f["label"] == 1)
    
    print(f"\n📊 DATASET STATISTICS:")
    print(f"  Total examples: {len(all_features)}")
    print(f"  Anomaly examples (label=-1): {anomaly_count}")
    print(f"  Normal examples (label=1): {normal_count}")
    
    return all_features

# ============================================
# STEP 7: MAIN EXECUTION
# ============================================
def main():
    print("=" * 60)
    print("MEGAVUL FEATURE EXTRACTION FOR ML")
    print("=" * 60)
    
    # Step 1: Load data
    data = load_megavul(MEGAVUL_FILE)
    
    # Step 2: Group by project
    projects = group_by_project(data)
    print(f"\nFound {len(projects)} projects with vulnerabilities")
    
    # Step 3: Create anomaly feature vectors
    anomaly_features = create_feature_vectors(projects)
    print(f"Created {len(anomaly_features)} anomaly examples")
    
    # Step 4: Create normal examples
    normal_features = create_normal_examples(projects, num_examples=800)
    
    # Step 5: Save to CSV
    all_features = save_to_csv(anomaly_features, normal_features, OUTPUT_CSV)
    
    # Step 6: Show sample
    print("\n📝 SAMPLE FEATURE VECTOR:")
    sample = all_features[0]
    for key, value in sample.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    main()