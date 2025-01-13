from pydantic import BaseModel

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    

class TokenRequest(BaseModel):
    code: str
    session_state: str
    state: str = None