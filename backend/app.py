from fastapi import FastAPI
from pydantic import BaseModel
import os
import subprocess
import json
import uuid
from datetime import datetime
from dotenv import load_dotenv
from models import ScanRequest  # Import your models
import shutil  # For cleanup

# Add these with your other imports
import joblib
import numpy as np
from pathlib import Path


# Ensure temp directory exists
# os.makedirs("C:\\temp", exist_ok=True)

SYFT_PATH = r"C:\Users\pc\AppData\Local\Microsoft\WinGet\Packages\Anchore.Syft_Microsoft.Winget.Source_8wekyb3d8bbwe\syft.exe"
TRIVY_PATH = r"C:\Users\pc\AppData\Local\Microsoft\WinGet\Packages\aquasecurity.trivy_Microsoft.Winget.Source_8wekyb3d8bbwe\trivy.exe"


load_dotenv()  # Load GitHub token from .env

app = FastAPI(title="Supply Chain Scanner API")



# ============================================
# LOAD ML MODEL (runs once when API starts)
# ============================================
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'final_anomaly_detector.pkl')
THRESHOLD_PATH = os.path.join(os.path.dirname(__file__), 'threshold.txt')

# Load model
if os.path.exists(MODEL_PATH):
    anomaly_model = joblib.load(MODEL_PATH)
    print(f"✅ ML Model loaded from {MODEL_PATH}")
else:
    anomaly_model = None
    print(f"⚠️ Model not found at {MODEL_PATH}")

# Load threshold
if os.path.exists(THRESHOLD_PATH):
    with open(THRESHOLD_PATH, 'r') as f:
        THRESHOLD = float(f.read().strip())
    print(f"✅ Threshold loaded: {THRESHOLD}")
else:
    THRESHOLD = -0.017  # Default from your training
    print(f"⚠️ Using default threshold: {THRESHOLD}")

# ============================================
# FIRST: Define ALL your helper functions
# ============================================

# async def clone_repository(repo_url: str, branch: str) -> str:
#     """Clone a GitHub repository using the token from .env"""
#     token = os.getenv("GITHUB_TOKEN")
#     repo_name = repo_url.split("/")[-1]
#     #scan_folder = f"temp_{repo_name}_{uuid.uuid4().hex}"  # Use local folder, not /tmp on Windows
    
#     scan_folder = f"C:\\temp\\{repo_name}_{uuid.uuid4().hex}"
#     if "github.com" in repo_url:
#         repo_path = "/".join(repo_url.split("/")[-2:]).replace(".git", "")
#         auth_url = f"https://x-access-token:{token}@github.com/{repo_path}.git"
#     else:
#         auth_url = repo_url
    
#     clone_command = ["git", "clone", "--branch", branch, "--depth", "1", auth_url, scan_folder]
    
#     try:
#         subprocess.run(clone_command, check=True, capture_output=True, text=True)
#         return scan_folder
#     except subprocess.CalledProcessError as e:
#         raise Exception(f"Failed to clone repository: {e.stderr}")


async def clone_repository(repo_url: str, branch: str) -> str:
    """Clone a GitHub repository with Windows long path support"""
    token = os.getenv("GITHUB_TOKEN")
    repo_name = repo_url.split("/")[-1]
    
    # Use shortest possible path
    scan_folder = f"C:\\temp\\{repo_name}_{uuid.uuid4().hex[:8]}"
    
    if "github.com" in repo_url:
        repo_path = "/".join(repo_url.split("/")[-2:]).replace(".git", "")
        auth_url = f"https://x-access-token:{token}@github.com/{repo_path}.git"
    else:
        auth_url = repo_url
    
    # Try normal clone first
    try:
        # Enable long paths in git (Windows-specific)
        subprocess.run(["git", "config", "--global", "core.longpaths", "true"], 
                      capture_output=True)
        
        clone_command = [
            "git", "clone", 
            "--branch", branch, 
            "--depth", "1",  # Shallow clone
            auth_url, 
            scan_folder
        ]
        
        result = subprocess.run(clone_command, check=True, 
                               capture_output=True, text=True)
        return scan_folder
        
    except subprocess.CalledProcessError as e:
        # If normal clone fails, try without checkout
        if "Filename too long" in e.stderr:
            print("⚠️ Path too long, trying sparse checkout...")
            
            # Initialize repo without checkout
            os.makedirs(scan_folder, exist_ok=True)
            subprocess.run(["git", "init"], cwd=scan_folder, check=True)
            subprocess.run(["git", "remote", "add", "origin", auth_url], 
                          cwd=scan_folder, check=True)
            subprocess.run(["git", "config", "core.longpaths", "true"], 
                          cwd=scan_folder)
            
            # Fetch only the branch
            subprocess.run(["git", "fetch", "--depth", "1", "origin", branch], 
                          cwd=scan_folder, check=True)
            subprocess.run(["git", "reset", "--hard", f"origin/{branch}"], 
                          cwd=scan_folder, check=True)
            
            return scan_folder
        else:
            raise Exception(f"Failed to clone repository: {e.stderr}")

# async def run_syft(repo_path: str) -> dict:
#     """Run Syft to get dependency information"""
#     try:
#         result = subprocess.run(
#             [SYFT_PATH, repo_path, "-o", "json"],
#             check=True,
#             capture_output=True,
#             text=True
#         )
#         syft_data = json.loads(result.stdout)
#         dependencies = syft_data.get("artifacts", [])
        
#         return {
#             "total_dependencies": len(dependencies),
#             "direct": 0,  # Will improve later
#             "outdated": 0,  # Will improve later
#             "raw_packages": dependencies
#         }
#     except Exception as e:
#         print(f"Syft error: {e}")
#         return {"total_dependencies": 0, "direct": 0, "outdated": 0, "raw_packages": []}


async def run_syft(repo_path: str) -> dict:
    """
    Run Syft to get dependency information with robust error handling
    """
    try:
        print(f"🔍 Running Syft on: {repo_path}")
        
        result = subprocess.run(
            [SYFT_PATH, repo_path, "-o", "json"],
            check=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=300  # 5 minute timeout
        )
        
        # Check if stdout is empty
        if not result.stdout or result.stdout.strip() == "":
            print("⚠️ Syft returned empty output")
            return {
                "total_dependencies": 0,
                "direct": 0,
                "outdated": 0,
                "raw_packages": []
            }
        
        # Try to parse JSON, handling potential warnings
        try:
            # Find first '{' in case there are warnings before JSON
            json_start = result.stdout.find('{')
            if json_start == -1:
                print("⚠️ No JSON found in Syft output")
                return {
                    "total_dependencies": 0,
                    "direct": 0,
                    "outdated": 0,
                    "raw_packages": []
                }
            
            # Extract just the JSON part
            json_str = result.stdout[json_start:]
            syft_data = json.loads(json_str)
            
        except json.JSONDecodeError as e:
            print(f"⚠️ Syft JSON parse error: {e}")
            print(f"First 200 chars of output: {result.stdout[:200]}")
            return {
                "total_dependencies": 0,
                "direct": 0,
                "outdated": 0,
                "raw_packages": []
            }
        
        # Extract dependencies
        dependencies = syft_data.get("artifacts", [])
        
        # Log success
        print(f"✅ Syft found {len(dependencies)} dependencies")
        
        return {
            "total_dependencies": len(dependencies),
            "direct": 0,  # Will improve later
            "outdated": 0,  # Will improve later
            "raw_packages": dependencies
        }
        
    except subprocess.TimeoutExpired:
        print("❌ Syft timed out after 5 minutes")
        return {
            "total_dependencies": 0,
            "direct": 0,
            "outdated": 0,
            "raw_packages": []
        }
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Syft process error: {e}")
        print(f"stderr: {e.stderr}")
        return {
            "total_dependencies": 0,
            "direct": 0,
            "outdated": 0,
            "raw_packages": []
        }
        
    except Exception as e:
        print(f"❌ Syft unexpected error: {e}")
        return {
            "total_dependencies": 0,
            "direct": 0,
            "outdated": 0,
            "raw_packages": []
        }

async def run_trivy(repo_path: str) -> list:
    """Run Trivy with robust error handling"""
    try:
        print(f"🔍 Running Trivy on: {repo_path}")
        
        result = subprocess.run(
            [TRIVY_PATH, "fs", "--format", "json", repo_path],
            check=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=600  # 10 minute timeout for Trivy
        )
        
        if not result.stdout or result.stdout.strip() == "":
            print("⚠️ Trivy returned empty output")
            return []
        
        # Find JSON start
        json_start = result.stdout.find('{')
        if json_start == -1:
            print("⚠️ No JSON found in Trivy output")
            return []
        
        json_str = result.stdout[json_start:]
        trivy_data = json.loads(json_str)
        
        vulnerabilities = []
        for result_item in trivy_data.get("Results", []):
            for vuln in result_item.get("Vulnerabilities", []):
                vulnerabilities.append({
                    "package": vuln.get("PkgName", "unknown"),
                    "version": vuln.get("InstalledVersion", "unknown"),
                    "severity": vuln.get("Severity", "UNKNOWN").upper(),
                    "cve": vuln.get("VulnerabilityID", ""),
                    "description": vuln.get("Title", "No description available")
                })
        
        print(f"✅ Trivy found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
        
    except subprocess.TimeoutExpired:
        print("❌ Trivy timed out")
        return []
    except subprocess.CalledProcessError as e:
        print(f"❌ Trivy process error: {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"❌ Trivy JSON error: {e}")
        return []
    except Exception as e:
        print(f"❌ Trivy unexpected error: {e}")
        return []

# async def run_trivy(repo_path: str) -> list:
#     try:
#         result = subprocess.run(
#             [TRIVY_PATH, "fs", "--format", "json", repo_path],
#             check=True,
#             capture_output=True,
#             text=True,
#             encoding='utf-8'  # ← ADD THIS!
#         )
#         trivy_data = json.loads(result.stdout)
#         vulnerabilities = []
        
#         for result_item in trivy_data.get("Results", []):
#             for vuln in result_item.get("Vulnerabilities", []):
#                 vulnerabilities.append({
#                     "package": vuln.get("PkgName", "unknown"),
#                     "version": vuln.get("InstalledVersion", "unknown"),
#                     "severity": vuln.get("Severity", "UNKNOWN").upper(),
#                     "cve": vuln.get("VulnerabilityID", ""),
#                     "description": vuln.get("Title", "No description available")
#                 })
#         return vulnerabilities
#     except Exception as e:
#         print(f"Trivy error: {e}")
#         return []



async def run_pip_audit(repo_path: str) -> list:
    """Run pip-audit for Python-specific vulnerabilities"""
    try:
        is_python = os.path.exists(os.path.join(repo_path, "requirements.txt")) or \
                    os.path.exists(os.path.join(repo_path, "setup.py"))
        
        if not is_python:
            return []
        
        result = subprocess.run(
            ["pip-audit", "--format", "json", repo_path],
            check=True,
            capture_output=True,
            text=True
        )
        pip_data = json.loads(result.stdout)
        vulnerabilities = []
        
        for dep in pip_data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                vulnerabilities.append({
                    "package": dep.get("name", "unknown"),
                    "version": dep.get("version", "unknown"),
                    "severity": vuln.get("severity", "UNKNOWN").upper(),
                    "cve": vuln.get("id", ""),
                    "description": vuln.get("description", "No description")
                })
        return vulnerabilities
    except Exception as e:
        print(f"pip-audit error: {e}")
        return []



def combine_results(syft_data: dict, trivy_vulns: list, pip_vulns: list) -> dict:
    """Combine all scan results into the required API format"""
    all_vulns = trivy_vulns.copy()
    pip_cves = {v["cve"] for v in pip_vulns}
    trivy_cves = {v["cve"] for v in trivy_vulns}
    
    for pip_vuln in pip_vulns:
        if pip_vuln["cve"] not in trivy_cves:
            all_vulns.append(pip_vuln)
    
    return {
        "sbom_summary": {
            "total_dependencies": syft_data["total_dependencies"],
            "direct": syft_data["direct"],
            "outdated": syft_data["outdated"]
        },
        "vulnerabilities": all_vulns
    }



def extract_repo_name(repo_url: str) -> str:
    """Extract owner/repo-name from GitHub URL"""
    url = repo_url.replace(".git", "")
    parts = url.split("/")
    return "/".join(parts[-2:])

# ============================================
# THEN: Define your endpoints
# ============================================

@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "Scanner API is running"}

# @app.post("/api/v1/scan")
# async def scan_repo(request: ScanRequest):
#     repo_path = None
#     try:
#         # Extract data from request
#         repo_url = request.repo_url
#         branch = request.branch
        
#         # Clone the repository
#         repo_path = await clone_repository(repo_url, branch)
        
#         # Run all scanners
#         syft_data = await run_syft(repo_path)
#         trivy_vulns = await run_trivy(repo_path)
#         pip_vulns = await run_pip_audit(repo_path)
        
#         # Combine results
#         scan_results = combine_results(syft_data, trivy_vulns, pip_vulns)
        
#         # Return formatted response
#         return {
#             "status": "success",
#             "scan_id": str(uuid.uuid4()),
#             "repo": extract_repo_name(repo_url),
#             "branch": branch,
#             "timestamp": datetime.utcnow().isoformat() + "Z",
#             "scan": scan_results,
#             "slsa": {"level": None, "issues": [], "suggestions": []},
#             "ai_risk": {"score": None, "level": None, "explanation": None, 
#                        "anomalies": [], "top_factors": []},
#             "errors": []
#         }
    
#     except PermissionError:
#         return {
#             "status": "error",
#             "code": "unauthorized",
#             "message": "Private repository requires a valid GitHub token"
#         }, 403
    
#     except Exception as e:
#         return {
#             "status": "error",
#             "code": "scan_failed",
#             "message": str(e)
#         }, 500
    
#     finally:
#         # Clean up: delete cloned repo
#         if repo_path and os.path.exists(repo_path):
#             shutil.rmtree(repo_path, ignore_errors=True)


# ============================================
# FEATURE EXTRACTION FOR ML MODEL
# ============================================
def extract_features_for_model(syft_data: dict, vulnerabilities: list) -> np.ndarray:
    """
    Convert scan results into feature vector for the ML model
    Must match the features used during training
    """
    # Count vulnerabilities by severity
    vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "").upper()
        if "CRITICAL" in severity:
            vuln_counts["critical"] += 1
        elif "HIGH" in severity:
            vuln_counts["high"] += 1
        elif "MEDIUM" in severity:
            vuln_counts["medium"] += 1
        elif "LOW" in severity:
            vuln_counts["low"] += 1
    
    # Create feature vector in EXACT order used during training
    features = np.array([[
        syft_data.get("total_dependencies", 0),
        syft_data.get("direct", 0),
        syft_data.get("outdated", 0),
        vuln_counts["critical"],
        vuln_counts["high"],
        vuln_counts["medium"],
        vuln_counts["low"],
        len(vulnerabilities)  # total_vulns
    ]])
    
    return features

@app.post("/api/v1/scan")
async def scan_repo(request: ScanRequest):
    repo_path = None
    try:
        # Extract data from request
        repo_url = request.repo_url
        branch = request.branch
        
        # Clone repository
        repo_path = await clone_repository(repo_url, branch)
        
        # Run scanners
        syft_data = await run_syft(repo_path)
        trivy_vulns = await run_trivy(repo_path)
        pip_vulns = await run_pip_audit(repo_path)
        
        # Combine vulnerabilities
        all_vulns = combine_vulnerabilities(trivy_vulns, pip_vulns)
        
        # ===== NEW: ML PREDICTION =====
        ml_result = {
            "score": None,
            "level": "UNKNOWN",
            "explanation": "Model not available",
            "anomalies": [],
            "top_factors": []
        }
        
        if anomaly_model is not None:
            # Extract features
            features = extract_features_for_model(syft_data, all_vulns)
            
            # Get anomaly score (more negative = more anomalous)
            score = anomaly_model.decision_function(features)[0]
            
            # Determine if anomaly using threshold
            is_anomaly = score < THRESHOLD
            
            # Create explanation
            if is_anomaly:
                level = "HIGH"
                explanation = f"Anomaly detected (score: {score:.3f}). Unusual pattern compared to normal projects."
                anomalies = ["Unusual dependency/vulnerability pattern detected"]
            else:
                level = "LOW" 
                explanation = f"Normal pattern detected (score: {score:.3f}). Project looks typical."
                anomalies = []
            
            ml_result = {
                "score": float(score),
                "level": level,
                "explanation": explanation,
                "anomalies": anomalies,
                "top_factors": [
                    {"factor": "critical_vulns", "weight": 45},
                    {"factor": "total_vulns", "weight": 30},
                    {"factor": "outdated_count", "weight": 25}
                ]
            }
        # ===== END ML PREDICTION =====
        
        # Count vulnerabilities by severity for response
        vuln_counts = {
            "critical": sum(1 for v in all_vulns if v.get("severity") == "CRITICAL"),
            "high": sum(1 for v in all_vulns if v.get("severity") == "HIGH"),
            "medium": sum(1 for v in all_vulns if v.get("severity") == "MEDIUM"),
            "low": sum(1 for v in all_vulns if v.get("severity") == "LOW")
        }
        
        # Return complete response
        return {
            "status": "success",
            "scan_id": str(uuid.uuid4()),
            "repo": extract_repo_name(repo_url),
            "branch": branch,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "slsa": {"level": None, "issues": [], "suggestions": []},  # Sara fills this
            "scan": {
                "sbom_summary": {
                    "total_dependencies": syft_data.get("total_dependencies", 0),
                    "direct": syft_data.get("direct", 0),
                    "outdated": syft_data.get("outdated", 0)
                },
                "vulnerabilities": all_vulns,
                "summary": {
                    "by_severity": vuln_counts
                }
            },
            "ai_risk": ml_result,  # ← Your ML prediction goes here!
            "errors": []
        }
        
    except PermissionError:
        return {
            "status": "error",
            "code": "unauthorized",
            "message": "Private repository requires a valid GitHub token"
        }, 403
        
    except Exception as e:
        return {
            "status": "error",
            "code": "scan_failed",
            "message": str(e)
        }, 500
        
    finally:
        # Clean up cloned repo
        if repo_path and os.path.exists(repo_path):
            import shutil
            shutil.rmtree(repo_path, ignore_errors=True)

def combine_vulnerabilities(trivy_vulns: list, pip_vulns: list) -> list:
    """Combine and deduplicate vulnerabilities from different sources"""
    all_vulns = trivy_vulns.copy()
    
    # Add pip-audit vulns not already in trivy
    pip_cves = {v.get("cve") for v in pip_vulns if v.get("cve")}
    trivy_cves = {v.get("cve") for v in trivy_vulns if v.get("cve")}
    
    for pip_vuln in pip_vulns:
        if pip_vuln.get("cve") not in trivy_cves:
            all_vulns.append(pip_vuln)
    
    return all_vulns

