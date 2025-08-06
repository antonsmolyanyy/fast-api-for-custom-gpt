from fastapi import FastAPI, Security, HTTPException, Request, Form
from fastapi.responses import RedirectResponse
from app.auth import TokenVerifier
import httpx
import json
from typing import Optional
from app.config import get_settings
import urllib.request

# We use PyJWKClient, which internally uses Python's built-in urllib.request, which sends requests
# without a standard User-Agent header (e.g., it sends "Python-urllib/3.x").
# Some CDNs or API gateways (like the one serving Descope's JWKS) may block such requests as they resemble bot traffic or security scanners.
opener = urllib.request.build_opener()
opener.addheaders = [('User-agent', 'Mozilla/5.0 (DescopeFastAPISampleApp)')]
urllib.request.install_opener(opener)
config = get_settings()

app = FastAPI()
auth = TokenVerifier()

@app.get("/")
def root():
    """Root endpoint - API information"""
    return {
        "message": "FastAPI Sample App with Descope Authentication",
        "version": "1.0.0",
        "endpoints": {
            "public": "/api/public",
            "private": "/api/private",
            "scoped_usage_read": "/api/private-scoped/usage/read",
            "scoped_logs_read": "/api/private-scoped/logs/read",
            "scoped_ci_trigger": "/api/private-scoped/ci/trigger",
            "scoped_ci_read": "/api/private-scoped/ci/read",
            "external_users": "/api/external/users",
            "external_weather": "/api/external/weather",
            "custom_api": "/api/custom/{endpoint}"
        },
        "oauth_endpoints": {
            "authorize": "/authorize",
            "token": "/token"
        },
        "docs": "/docs",
        "redoc": "/redoc"
    }

@app.get("/authorize")
async def authorize(
    response_type: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    scope: Optional[str] = None,
    state: Optional[str] = None
):
    """
    OAuth 2.0 Authorization Endpoint - Proxies to Descope
    
    This endpoint forwards OAuth authorization requests to Descope's Inbound Apps.
    """
    try:
        # Validate required parameters
        if not redirect_uri or not response_type:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_request",
                    "error_description": f"Missing required parameters + {bool(redirect_uri)} + {bool(response_type)}"
                }
            )

        # Validate response_type
        if response_type != "code":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "unsupported_response_type",
                    "error_description": 'Only "code" is supported'
                }
            )
        
        # Get client ID from environment or use the provided one
        descope_client_id = get_settings().descope_inbound_app_client_id
        
        # Construct query parameters
        params = {
            "client_id": descope_client_id,
            "redirect_uri": "https://fast-api-for-custom-gpt.vercel.app/api/oauth/callback",  # Your actual ngrok URL
            "response_type": "code",
            "scope": scope or "openid",
            "state": state or ""  # Just pass through the state parameter
        }
        
        # Build the full URL with query parameters
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        full_url = f"https://api.descope.com/oauth2/v1/apps/authorize?{query_string}"
        
        # Redirect to Descope's authorization endpoint
        return RedirectResponse(url=full_url)
        
    except HTTPException:
        raise
    except Exception as error:
        print(f"Authorization endpoint error: {error}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "server_error",
                "error_description": f"Internal server error + {descope_client_id}"
            }
        )

@app.post("/token")
async def token(
    request: Request
):
    """
    OAuth 2.0 Token Endpoint - Proxies to Descope
    
    This endpoint forwards token exchange requests to Descope's Inbound Apps.
    """
    try:
        # Parse the request body based on content type
        content_type = request.headers.get("content-type", "")
        
        if "application/json" in content_type:
            body = await request.json()
        elif "application/x-www-form-urlencoded" in content_type:
            form_data = await request.form()
            body = dict(form_data)
        else:
            # Try to parse as JSON first, then as form data
            try:
                body = await request.json()
            except:
                form_data = await request.form()
                body = dict(form_data)
        
        grant_type = body.get("grant_type")
        code = body.get("code")
        client_id = config.descope_inbound_app_client_id
        client_secret = config.descope_inbound_app_client_secret

        # Validate required parameters
        if not grant_type or not code or not client_id or not client_secret:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_request",
                    "error_description": f"Missing required parameters + {bool(grant_type)} + {bool(code)} + {bool(client_id)} + {bool(client_secret)}"
                }
            )

        # Only support authorization_code grant type
        if grant_type != "authorization_code":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "unsupported_grant_type",
                    "error_description": "Only authorization_code is supported"
                }
            )

        # Check if we have the required environment variables
        if not config.descope_inbound_app_client_id or not config.descope_inbound_app_client_secret:
            print("Missing environment variables for token exchange")
            print(f"CLIENT_ID: {bool(config.descope_inbound_app_client_id)}")
            print(f"CLIENT_SECRET: {bool(config.descope_inbound_app_client_secret)}")
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "server_error",
                    "error_description": "OAuth configuration incomplete"
                }
            )

        # Forward the request to Descope's token endpoint
        token_request_body = {
            "grant_type": "authorization_code",
            "client_id": config.descope_inbound_app_client_id,
            "client_secret": config.descope_inbound_app_client_secret,
            "code": code,
            "redirect_uri": "https://fast-api-for-custom-gpt.vercel.app/api/oauth/callback"  # Your actual ngrok URL
        }

        print(f"Token exchange request body: {token_request_body}")
        print(f"Token exchange URL: https://api.descope.com/oauth2/v1/apps/token")

        descope_url = "https://api.descope.com/oauth2/v1/apps/token"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                descope_url,
                data=token_request_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            descope_data = response.json()
            
            # Log the response for debugging
            print(f"Descope token response status: {response.status_code}")
            print(f"Descope token response data: {descope_data}")

            # If Descope returned an error, log it
            if response.status_code >= 400:
                print(f"Descope token exchange failed: {descope_data}")

            # Return the response from Descope
            return descope_data
            
    except HTTPException:
        raise
    except Exception as error:
        print(f"Token endpoint error: {error}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "server_error",
                "error_description": "Internal server error"
            }
        )

@app.get("/api/oauth/callback")
async def oauth_callback(
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None
):
    """
    OAuth 2.0 Callback Endpoint
    
    Handles the callback from Descope and redirects back to Custom GPT.
    """
    try:
        # Handle errors from Descope
        if error:
            print(f"Descope authorization error: {error}, {error_description}")
            raise HTTPException(
                status_code=400,
                detail={
                    "error": error,
                    "error_description": error_description
                }
            )

        if not code:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_request",
                    "error_description": "No authorization code received"
                }
            )

        # Custom GPT callback URL
        custom_gpt_callback = "https://chat.openai.com/aip/g-e3b7f2f4c25562eb30538a4f1aa74846326222f6/oauth/callback"
        
        # Build redirect URL back to Custom GPT
        redirect_url = f"{custom_gpt_callback}?code={code}"
        if state:
            redirect_url += f"&state={state}"
        
        print(f"Redirecting to: {redirect_url}")

        return RedirectResponse(url=redirect_url)
        
    except HTTPException:
        raise
    except Exception as error:
        print(f"Callback endpoint error: {error}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "server_error",
                "error_description": "Internal server error"
            }
        )


@app.get("/api/public")
def public():
    """Public Route: No Authentication required."""
    result = {
        "status": "success",
        "msg": "Success! This endpoint is publicly available and requires no authentication."
    }
    return result


@app.get("/api/private")
def private(auth_result: str = Security(auth)):
    """
    This is a protected route.

    Access to this endpoint requires a valid JWT access token.
    The `auth` dependency uses FastAPI's `Security` to perform token verification before entering this route.
    """
    return auth_result


@app.get("/api/private-scoped/usage/read")
def private_scoped(auth_result: str = Security(auth, scopes=['usage:read'])):
    """
    This is a protected route with scope-based access control.

    Access to this endpoint requires:
    - A valid access token (authentication), and
    - The presence of the `usage:read` scope in the token.
    """
    return auth_result

@app.get("/api/private-scoped/logs/read")
def private_scoped(auth_result: str = Security(auth, scopes=['logs:read'])):
    """
    This is a protected route with scope-based access control.

    Access to this endpoint requires:
    - A valid access token (authentication), and
    - The presence of the `logs:read` scope in the token.
    """
    return auth_result

@app.get("/api/private-scoped/ci/trigger")
def private_scoped(auth_result: str = Security(auth, scopes=['ci:trigger'])):
    """
    This is a protected route with scope-based access control.

    Access to this endpoint requires:
    - A valid access token (authentication), and
    - The presence of the `ci:trigger` scope in the token.
    """
    return auth_result

@app.get("/api/private-scoped/ci/read")
def private_scoped(auth_result: str = Security(auth, scopes=['ci:read'])):
    """
    This is a protected route with scope-based access control.

    Access to this endpoint requires:
    - A valid access token (authentication), and
    - The presence of the `ci:read` scope in the token.
    """
    return auth_result

# Example: Call external API (JSONPlaceholder)
@app.get("/api/external/users")
async def get_external_users():
    """Example: Call external API to get users"""
    async with httpx.AsyncClient() as client:
        response = await client.get("https://jsonplaceholder.typicode.com/users")
        return {
            "status": "success",
            "data": response.json(),
            "source": "External API: JSONPlaceholder"
        }

# Example: Call external API with authentication
@app.get("/api/external/weather")
async def get_weather(auth_result: str = Security(auth)):
    """Example: Call weather API (requires authentication)"""
    # You would replace this with your actual weather API
    async with httpx.AsyncClient() as client:
        # Example API call (replace with your actual API)
        response = await client.get("https://api.openweathermap.org/data/2.5/weather?lat=45.540237&lon=13.731839&appid=6b0bb55a1a72b6fefb0b5abc1e72ced4")
        return {
            "status": "success",
            "user": auth_result,
            "weather_data": response.json(),
            "source": "External API: OpenWeatherMap"
        }

# Example: Call your own custom API
@app.get("/api/custom/{endpoint}")
async def call_custom_api(endpoint: str, auth_result: str = Security(auth)):
    """Example: Call your custom API with dynamic endpoint"""
    # Replace with your actual API base URL
    base_url = "https://your-api.com/api"

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{base_url}/{endpoint}")
        return {
            "status": "success",
            "user": auth_result,
            "endpoint": endpoint,
            "data": response.json(),
            "source": f"Custom API: {base_url}"
        }
