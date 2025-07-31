from fastapi import FastAPI, Security
from fastapi.responses import HTMLResponse
from app.auth import TokenVerifier
import httpx

import urllib.request

# We use PyJWKClient, which internally uses Python's built-in urllib.request, which sends requests
# without a standard User-Agent header (e.g., it sends "Python-urllib/3.x").
# Some CDNs or API gateways (like the one serving Descope's JWKS) may block such requests as they resemble bot traffic or security scanners.
opener = urllib.request.build_opener()
opener.addheaders = [('User-agent', 'Mozilla/5.0 (DescopeFastAPISampleApp)')]
urllib.request.install_opener(opener)

app = FastAPI()
auth = TokenVerifier()

@app.get("/", response_class=HTMLResponse)
def root():
    """Root endpoint with simple HTML frontend"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>FastAPI Sample App</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }
            .public { border-left: 4px solid #28a745; }
            .private { border-left: 4px solid #007bff; }
            .scoped { border-left: 4px solid #ffc107; }
            .external { border-left: 4px solid #17a2b8; }
            a { color: #007bff; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>🚀 FastAPI Sample App with Descope Authentication</h1>
        <p>This is a sample API demonstrating authentication and authorization with Descope.</p>
        
        <h2>📋 Available Endpoints</h2>
        
        <div class="endpoint public">
            <h3>🌐 Public Endpoints (No Auth Required)</h3>
            <ul>
                <li><a href="/api/public" target="_blank">/api/public</a> - Public endpoint</li>
                <li><a href="/api/external/users" target="_blank">/api/external/users</a> - External API call</li>
            </ul>
        </div>
        
        <div class="endpoint private">
            <h3>🔐 Private Endpoints (Auth Required)</h3>
            <ul>
                <li><a href="/api/private" target="_blank">/api/private</a> - Requires valid JWT</li>
                <li><a href="/api/external/weather" target="_blank">/api/external/weather</a> - Weather API with auth</li>
            </ul>
        </div>
        
        <div class="endpoint scoped">
            <h3>🎯 Scoped Endpoints (Auth + Specific Permissions)</h3>
            <ul>
                <li><a href="/api/private-scoped/readonly" target="_blank">/api/private-scoped/readonly</a> - Requires 'read:messages' scope</li>
                <li><a href="/api/private-scoped/write" target="_blank">/api/private-scoped/write</a> - Requires 'read:messages' and 'write:messages' scopes</li>
                <li><a href="/api/private-scoped/delete" target="_blank">/api/private-scoped/delete</a> - Requires 'delete:messages' scope</li>
            </ul>
        </div>
        
        <div class="endpoint external">
            <h3>📚 Documentation</h3>
            <ul>
                <li><a href="/docs" target="_blank">/docs</a> - Interactive API documentation</li>
                <li><a href="/redoc" target="_blank">/redoc</a> - Alternative API documentation</li>
            </ul>
        </div>
        
        <p><strong>Note:</strong> Private and scoped endpoints require a valid JWT access token in the Authorization header.</p>
    </body>
    </html>
    """

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
