from functools import lru_cache
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os

load_dotenv()

class Settings(BaseSettings):
    descope_project_id: str = os.getenv("DESCOPE_PROJECT_ID")  # Default for deployment
    descope_api_base_url: str = "https://api.descope.com"  # Default for deployment
    descope_inbound_app_client_id: str = os.getenv("DESCOPE_INBOUND_APP_CLIENT_ID")  # Set via environment variable
    descope_inbound_app_client_secret: str = os.getenv("DESCOPE_INBOUND_APP_CLIENT_SECRET")  # Set via environment variable

    class Config:
        env_file = ".env"

    @property
    def issuer_candidates(self) -> str:
        # the 'iss' field is the Descope Project ID.
        return [f'https://api.descope.com/v1/apps/{self.descope_project_id}', self.descope_project_id]

    @property
    def audience(self) -> str:
        return self.descope_project_id
 
    @property
    def jwks_url(self) -> str:
        return f"{self.descope_api_base_url.rstrip('/')}/{self.descope_project_id}/.well-known/jwks.json"

@lru_cache()
def get_settings():
    return Settings()
