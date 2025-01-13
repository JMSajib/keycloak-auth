import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # # Add this line
    BASE_URL: str = "http://127.0.0.1:3000"
    SECRET_KEY: str = "your-super-secret-key"  #for session encryption
    
    DATABASE_URL: str
    JWT_ALGORITHM: str
    
    KEYCLOAK_URL: str = "http://localhost:8080"
    KEYCLOAK_REALM: str = 'sso-realm'
    KEYCLOAK_CLIENT_ID: str = 'sso-client'
    KEYCLOAK_CLIENT_SECRET: str = 'WFNOllvRvsNtOp1exzV9Iix3NYV9XuI7'
    KEYCLOAK_ADMIN_USERNAME: str = 'jmsajibcse@gmail.com'
    KEYCLOAK_ADMIN_PASSWORD: str = '@Pass12345'
    
    FRONTEND_BASE_URL:str = os.getenv("FRONTEND_BASE_URL")
    FRONTEND_REDIRECT_URL:str = os.getenv("FRONTEND_REDIRECT_URL")
    BACKEND_BASE_URL:str = os.getenv("BACKEND_BASE_URL")

    REDIS_HOST:str = os.getenv("REDIS_HOST")
    REDIS_PORT:int = os.getenv("REDIS_PORT")
    REDIS_DB:int = os.getenv("REDIS_DB")

    SP_ACS_URL:str = os.getenv("SP_ACS_URL")
    SP_SLO_URL:str = os.getenv("SP_SLO_URL")
    SP_CERT:str = os.getenv("SP_CERT")
    SP_KEY:str = os.getenv("SP_KEY")

    IDP_ENTITY_ID:str = os.getenv("IDP_ENTITY_ID")
    IDP_SSO_URL:str = os.getenv("IDP_SSO_URL")
    IDP_SLO_URL:str = os.getenv("IDP_SLO_URL")
    IDP_CERT:str = os.getenv("IDP_CERT")

    SECRET_KEY = os.getenv("SECRET_KEY")
    
    PROJECT_NAME: str = "Auth API"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


Config = Settings()