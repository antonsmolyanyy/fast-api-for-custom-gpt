from fastapi import FastAPI, Security, HTTPException, Request, Form
from fastapi.responses import RedirectResponse
from app.auth import TokenVerifier
import httpx
from typing import Optional

import urllib.request

# We use PyJWKClient, which internally uses Python's built-in urllib.request, which sends requests
# without a standard User-Agent header (e.g., it sends "Python-urllib/3.x").
# Some CDNs or API gateways (like the one serving Descope's JWKS) may block such requests as they resemble bot traffic or security scanners.
opener = urllib.request.build_opener()
opener.addheaders = [('User-agent', 'Mozilla/5.0 (DescopeFastAPISampleApp)')]
urllib.request.install_opener(opener)

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
            "scoped_readonly": "/api/private-scoped/readonly",
            "scoped_write": "/api/private-scoped/write", 
            "scoped_delete": "/api/private-scoped/delete",
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
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: Optional[str] = None,
    state: Optional[str] = None
):
    """
    OAuth 2.0 Authorization Endpoint - Proxies to Descope
    
    This endpoint forwards OAuth authorization requests to Descope's Inbound Apps.
    """
    # Build the Descope authorization URL
    descope_url = "https://api.descope.com/oauth2/v1/apps/authorize"
    
    # Construct query parameters
    params = {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri
    }
    
    if scope:
        params["scope"] = scope
    if state:
        params["state"] = state
    
    # Build the full URL with query parameters
    query_string = "&".join([f"{k}={v}" for k, v in params.items()])
    full_url = f"{descope_url}?{query_string}"
    
    # Redirect to Descope's authorization endpoint
    return RedirectResponse(url=full_url)

@app.post("/token")
async def token(
    request: Request
):
    """
    OAuth 2.0 Token Endpoint - Proxies to Descope
    
    This endpoint forwards token exchange requests to Descope's Inbound Apps.
    """
    # Get the form data from the request
    form_data = await request.form()
    
    # Forward the request to Descope's token endpoint
    descope_url = "https://api.descope.com/oauth2/v1/apps/token"
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            descope_url,
            data=dict(form_data),
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        # Return the response from Descope
        return response.json()


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


@app.get("/api/private-scoped/readonly")
def private_scoped(auth_result: str = Security(auth, scopes=['read:messages'])):
    """
    This is a protected route with scope-based access control.

    Access to this endpoint requires:
    - A valid access token (authentication), and
    - The presence of the `read:messages` scope in the token.
    """
    return auth_result

@app.get("/api/private-scoped/write")
def private_scoped(auth_result: str = Security(auth, scopes=['read:messages', 'write:messages'])):
    """
    This is a protected route with scope-based access control.

    Access to this endpoint requires:
    - A valid access token (authentication), and
    - The presence of the `read:messages` and `write:messages` scope in the token.
    """
    return auth_result

@app.get("/api/private-scoped/delete")
def private_scoped(auth_result: str = Security(auth, scopes=['delete:messages'])):
    """
    This is a protected route with scope-based access control.

    Access to this endpoint requires:
    - A valid access token (authentication), and
    - The presence of the `delete:messages` scope in the token.
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
