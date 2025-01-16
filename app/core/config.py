import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # # Add this line
    BASE_URL: str = "http://127.0.0.1:3000"
    
    DATABASE_URL: str
    JWT_ALGORITHM: str
    
    KEYCLOAK_URL: str = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
    KEYCLOAK_REALM: str = 'sso-realm'
    KEYCLOAK_CLIENT_ID: str = 'sso-client'
    KEYCLOAK_CLIENT_SECRET: str
    KEYCLOAK_ADMIN_USERNAME: str = 'jmsajibcse@gmail.com'
    KEYCLOAK_ADMIN_PASSWORD: str = '@Pass12345'
    
    # Internal URLs (for service-to-service communication)
    KEYCLOAK_INTERNAL_URL:str = "http://keycloak:8080"
    KEYCLOAK_REALM:str = "sso-realm"
    
    # External URLs (for browser-to-keycloak communication)
    KEYCLOAK_EXTERNAL_URL:str = "https://keycloak.jmsajib.com"
    
    # Use internal URL for token validation and userinfo
    USERINFO_URL:str = f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
    TOKEN_URL:str = f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    
    # Use external URL for redirects and frontend communication
    AUTHORIZATION_URL:str = f"{KEYCLOAK_EXTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
    REDIRECT_URI:str = "http://localhost:3000/auth/callback"  # or your actual redirect URI
    
    
    FRONTEND_BASE_URL:str = os.getenv("FRONTEND_BASE_URL", "http://localhost:3000")
    FRONTEND_REDIRECT_URL:str = os.getenv("FRONTEND_REDIRECT_URL")
    BACKEND_BASE_URL:str = os.getenv("BACKEND_BASE_URL")

    REDIS_HOST:str = os.getenv("REDIS_HOST")
    REDIS_PORT:int = os.getenv("REDIS_PORT")
    REDIS_DB:int = os.getenv("REDIS_DB")

    SECRET_KEY:str = os.getenv("SECRET_KEY")
    
    PROJECT_NAME: str = "Auth API"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


Config = Settings()