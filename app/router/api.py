from fastapi import APIRouter

router = APIRouter()

@router.post("/token/")
def token_endpoint():
    # Here recieve auth_code, grant_type ("authorization_code") and redirect_uri
    # In header recieve client_id and client_secret from "Authorization" header
    # In respone return access_token, refresh_token, expires_in
    pass