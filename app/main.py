from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.apis.v1.oidc_auth.routes import auth_router
from app.apis.v1.saml_auth.routes import auth_saml
from app.core.redis_client import check_redis_connection

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    check_redis_connection()
    print("Starting up the application...")
    yield
    # Shutdown
    print("Shutting down the application...")

def create_app() -> FastAPI:
    app = FastAPI(
        title="Auth API",
        description="REST API for Auth service",
        version="1.0.0",
        lifespan=lifespan
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    register_routers(app)
    
    return app

def register_routers(app: FastAPI) -> None:
    """Register all routers for the application."""
    app.include_router(auth_router, prefix="/api/v1/auth/oidc")
    app.include_router(auth_saml, prefix="/api/v1/auth/saml")

# Create the application instance
app = create_app()

