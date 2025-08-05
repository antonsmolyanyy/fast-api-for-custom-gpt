#!/usr/bin/env python3
"""
Debug script to help troubleshoot JWT token validation issues
"""
import jwt
import requests
import json
from urllib.parse import urlparse

def decode_jwt_header(token):
    """Decode the JWT header without verification"""
    try:
        header = jwt.get_unverified_header(token)
        return header
    except Exception as e:
        print(f"Error decoding JWT header: {e}")
        return None

def fetch_jwks(jwks_url):
    """Fetch the JWKS from the provided URL"""
    try:
        response = requests.get(jwks_url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching JWKS: {e}")
        return None

def check_key_in_jwks(jwks, kid):
    """Check if a specific key ID exists in the JWKS"""
    if not jwks or 'keys' not in jwks:
        print("Invalid JWKS format")
        return False
    
    for key in jwks['keys']:
        if key.get('kid') == kid:
            print(f"✅ Key ID '{kid}' found in JWKS")
            print(f"   Key type: {key.get('kty')}")
            print(f"   Algorithm: {key.get('alg')}")
            return True
    
    print(f"❌ Key ID '{kid}' NOT found in JWKS")
    print("Available key IDs:")
    for key in jwks['keys']:
        print(f"   - {key.get('kid')}")
    return False

def main():
    print("🔍 JWT Token Debug Tool")
    print("=" * 50)
    
    # Get token from user
    token = input("Enter your JWT token: ").strip()
    if not token:
        print("No token provided")
        return
    
    # Decode header to get key ID
    header = decode_jwt_header(token)
    if not header:
        return
    
    kid = header.get('kid')
    if not kid:
        print("❌ No 'kid' (key ID) found in JWT header")
        return
    
    print(f"🔑 Key ID from token: {kid}")
    print(f"📝 Algorithm: {header.get('alg')}")
    print(f"📝 Token type: {header.get('typ')}")
    
    # Get project ID from user
    project_id = input("Enter your Descope Project ID: ").strip()
    if not project_id:
        print("No project ID provided")
        return
    
    # Construct JWKS URL
    jwks_url = f"https://api.descope.com/{project_id}/.well-known/jwks.json"
    print(f"🌐 JWKS URL: {jwks_url}")
    
    # Fetch JWKS
    print("\n📥 Fetching JWKS...")
    jwks = fetch_jwks(jwks_url)
    if not jwks:
        return
    
    # Check if key exists
    print(f"\n🔍 Checking if key '{kid}' exists in JWKS...")
    key_exists = check_key_in_jwks(jwks, kid)
    
    if not key_exists:
        print("\n💡 Troubleshooting suggestions:")
        print("1. Verify your Project ID is correct")
        print("2. Make sure the token is from the same Descope project")
        print("3. Check if the token is expired")
        print("4. Ensure you're using the correct environment (dev/staging/prod)")
    else:
        print("\n✅ The key exists in JWKS. The issue might be:")
        print("1. Token expiration")
        print("2. Incorrect audience or issuer")
        print("3. Token format issues")

if __name__ == "__main__":
    main() 