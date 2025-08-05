#!/usr/bin/env python3
"""
Setup script to configure environment variables for Descope FastAPI app
"""
import os
import sys

def create_env_file():
    """Create a .env file with the required environment variables"""
    
    print("🔧 Descope FastAPI Environment Setup")
    print("=" * 50)
    
    # Get project ID from user
    project_id = input("Enter your Descope Project ID: ").strip()
    if not project_id:
        print("❌ Project ID is required")
        return False
    
    # Get client ID and secret (optional for basic setup)
    client_id = input("Enter your Descope Inbound App Client ID (optional): ").strip()
    client_secret = input("Enter your Descope Inbound App Client Secret (optional): ").strip()
    
    # Create .env content
    env_content = f"""# Descope Configuration
DESCOPE_PROJECT_ID={project_id}
DESCOPE_INBOUND_APP_CLIENT_ID={client_id or 'dummy-client-id'}
DESCOPE_INBOUND_APP_CLIENT_SECRET={client_secret or 'dummy-client-secret'}
"""
    
    # Write to .env file
    try:
        with open('.env', 'w') as f:
            f.write(env_content)
        print("✅ .env file created successfully!")
        print(f"📁 Project ID: {project_id}")
        if client_id:
            print(f"🔑 Client ID: {client_id}")
        else:
            print("⚠️  Client ID not set - OAuth features will be limited")
        return True
    except Exception as e:
        print(f"❌ Error creating .env file: {e}")
        return False

def verify_jwks_url(project_id):
    """Verify that the JWKS URL is accessible"""
    import requests
    
    jwks_url = f"https://api.descope.com/{project_id}/.well-known/jwks.json"
    print(f"\n🔍 Verifying JWKS URL: {jwks_url}")
    
    try:
        response = requests.get(jwks_url)
        if response.status_code == 200:
            jwks = response.json()
            key_count = len(jwks.get('keys', []))
            print(f"✅ JWKS URL is accessible")
            print(f"📊 Found {key_count} signing keys")
            return True
        else:
            print(f"❌ JWKS URL returned status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error accessing JWKS URL: {e}")
        return False

def main():
    if create_env_file():
        # Get project ID from the file we just created
        with open('.env', 'r') as f:
            for line in f:
                if line.startswith('DESCOPE_PROJECT_ID='):
                    project_id = line.split('=')[1].strip()
                    break
        
        print("\n🔍 Verifying configuration...")
        if verify_jwks_url(project_id):
            print("\n✅ Setup completed successfully!")
            print("\n🚀 Next steps:")
            print("1. Start the server: uvicorn app.main:app --reload")
            print("2. Test the public endpoint: http://localhost:8000/api/public")
            print("3. Get a valid token from your Descope project")
            print("4. Test protected endpoints with the token")
        else:
            print("\n⚠️  Setup completed but JWKS verification failed.")
            print("Please check your Project ID and try again.")

if __name__ == "__main__":
    main() 