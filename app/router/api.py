from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from datetime import datetime


from app.schemas import PostTokenSchema
from app.database import get_db
from app.models import AuthorizationCode, ServiceProvider, User
from app.utils import create_access_token, create_refresh_token
import base64

router = APIRouter()

@router.post("/token/")
def token_endpoint(form_data: PostTokenSchema, request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Basic "):
        encoded_credentials = auth_header.split(" ")[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
        client_id, client_secret = decoded_credentials.split(":")

        authorization_code = db.query(AuthorizationCode).filter(AuthorizationCode.code == form_data.auth_code).first()

        if not authorization_code or authorization_code.is_used or authorization_code.expires_at < datetime.now():
            raise HTTPException(status_code=400, detail='Invalid authorization code')

        service_provider = db.query(ServiceProvider).filter(ServiceProvider.client_id == client_id).first()

        if authorization_code.service_provider_id != service_provider.id or service_provider.client_secret != client_secret:
            raise HTTPException(status_code=400, detail='Invalid client credentials')

        user = db.query(User).filter(User.id == authorization_code.user_id).first()

        if authorization_code.user_id != user.id:
            raise HTTPException(status_code=400, detail='Invalid user')

        access_token = create_access_token(data={"sub": user.id, "client_id": client_id})
        refresh_token = create_refresh_token(data={"sub": user.id, "client_id": client_id})

        response = {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

        return JSONResponse(content=response, status_code=200)
    else:
        raise HTTPException(status_code=400, detail="Invalid Authorization header")