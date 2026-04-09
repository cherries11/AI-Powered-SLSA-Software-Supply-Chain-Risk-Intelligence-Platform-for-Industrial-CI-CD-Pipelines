import os
from dotenv import load_dotenv
import subprocess
import requests

load_dotenv()
token = os.getenv("GITHUB_TOKEN")

print("=" * 50)
print("GITHUB TOKEN TEST")
print("=" * 50)

# Test 1: Check if token exists
print(f"\n📌 Test 1: Token loaded?")
if token:
    print(f"  ✅ YES - Token found")
    print(f"  Token starts with: {token[:4]}...")
    print(f"  Token length: {len(token)} characters")
else:
    print(f"  ❌ NO - Token not found in .env file")
    print(f"  Current directory: {os.getcwd()}")
    print(f"  .env exists? {os.path.exists('.env')}")

# Test 2: Test token with GitHub API
print(f"\n📌 Test 2: Testing token with GitHub API...")

if token:
    # Test public repo access
    headers = {"Authorization": f"token {token}"}
    test_url = "https://api.github.com/repos/pallets/flask"
    
    try:
        response = requests.get(test_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            print(f"  ✅ SUCCESS! Token works!")
            print(f"  Repo: {data['full_name']}")
            print(f"  Private: {data['private']}")
            print(f"  Stars: {data['stargazers_count']}")
            
            # Check rate limit
            rate_limit = requests.get("https://api.github.com/rate_limit", headers=headers)
            if rate_limit.status_code == 200:
                limit_data = rate_limit.json()
                remaining = limit_data['resources']['core']['remaining']
                print(f"  Rate limit remaining: {remaining}/5000")
                
        elif response.status_code == 401:
            print(f"  ❌ Token is invalid or expired")
        elif response.status_code == 403:
            print(f"  ❌ Token rate limited or wrong permissions")
        else:
            print(f"  ❌ Unknown error: {response.status_code}")
            
    except Exception as e:
        print(f"  ❌ Error: {e}")
else:
    print(f"  ⚠️ Skipping API test - no token")

# Test 3: Test git clone with token
print(f"\n📌 Test 3: Testing git clone with token...")

if token:
    test_repo = "https://github.com/pallets/flask"
    repo_name = "flask_test"
    
    # Extract owner/repo
    owner_repo = "pallets/flask"
    auth_url = f"https://x-access-token:{token}@github.com/{owner_repo}.git"
    
    print(f"  Attempting to clone {owner_repo}...")
    
    try:
        # Try shallow clone (faster)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", auth_url, repo_name],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print(f"  ✅ SUCCESS! Repository cloned!")
            
            # Clean up
            import shutil
            shutil.rmtree(repo_name, ignore_errors=True)
            print(f"  Cleaned up test folder")
        else:
            print(f"  ❌ Clone failed:")
            print(f"  Error: {result.stderr[:200]}...")
            
    except subprocess.TimeoutExpired:
        print(f"  ❌ Clone timed out")
    except Exception as e:
        print(f"  ❌ Error: {e}")
else:
    print(f"  ⚠️ Skipping clone test - no token")

print("\n" + "=" * 50)
print("TEST COMPLETE")
print("=" * 50)