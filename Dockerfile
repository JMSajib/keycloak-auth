# Builder stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Final stage
FROM python:3.11-slim

WORKDIR /app

# Copy only the necessary Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=builder /app .

# Set environment variables
ENV DATABASE_URL="postgresql+asyncpg://postgres:mysecretpassword@app_postgres:5432/auth_db" \
    REDIS_HOST="redis" \
    REDIS_PORT=6379 \
    REDIS_DB=0 \
    SECRET_KEY="WhDF1_-BQnWJQRFfuKQUeRU-zGpo6DZyiA270tTG0_g" \
    FRONTEND_BASE_URL="https://jmsajib.com" \
    FRONTEND_REDIRECT_URL="https://jmsajib.com/auth/callback" \
    BACKEND_BASE_URL="https://jmsajib.com" \
    KEYCLOAK_URL="http://keycloak:8080" \
    KEYCLOAK_CLIENT_SECRET="PF6SDtttBsoSVdv0KJAbc2nDhDSjpb0Y" \
    KC_HOSTNAME="keycloak" \
    KC_HOSTNAME_PORT=8080 \
    KC_HOSTNAME_STRICT="false" \
    KC_HOSTNAME_STRICT_HTTPS="false" \
    KEYCLOAK_FRONTEND_URL="http://keycloak:8080" \
    JWT_ALGORITHM=HS256

# Expose the port the app runs on
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "run:app", "--host", "0.0.0.0"]

# FROM python:3.11-slim

# WORKDIR /app

# # Install system dependencies
# RUN apt-get update && apt-get install -y \
#     gcc \
#     && rm -rf /var/lib/apt/lists/*

# ENV DATABASE_URL="postgresql+asyncpg://postgres:mysecretpassword@app_postgres:5432/auth_db" \
# REDIS_HOST="redis" \
# REDIS_PORT=6379 \
# REDIS_DB=0 \
# SECRET_KEY="WhDF1_-BQnWJQRFfuKQUeRU-zGpo6DZyiA270tTG0_g" \
# FRONTEND_BASE_URL="https://jmsajib.com" \
# FRONTEND_REDIRECT_URL="https://jmsajib.com/auth/callback" \
# BACKEND_BASE_URL="https://jmsajib.com" \
# KEYCLOAK_URL="http://keycloak:8080" \
# KEYCLOAK_CLIENT_SECRET="PF6SDtttBsoSVdv0KJAbc2nDhDSjpb0Y" \
# KC_HOSTNAME="keycloak" \
# KC_HOSTNAME_PORT=8080 \
# KC_HOSTNAME_STRICT="false" \
# KC_HOSTNAME_STRICT_HTTPS="false" \
# KEYCLOAK_FRONTEND_URL="http://keycloak:8080" \
# JWT_ALGORITHM=HS256

# # Copy requirements first to leverage Docker cache
# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt

# # Copy the rest of the application
# COPY . .

# # Expose the port the app runs on
# EXPOSE 8000

# # Command to run the application
# CMD ["uvicorn", "run:app", "--host", "0.0.0.0"]