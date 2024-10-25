from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app.utils import authenticate_user, create_access_token, create_refresh_token, create_session, verify_session, get_user_by_id, decode_token, JWTBearer, get_current_user, decode_refresh_token
from app.schemas import DeveloperLoginSchema, GetDeveloperDetailsSchema
from app.models import User
from app.database import get_db

router = APIRouter()

@router.post("/login/")
def login_endpoint(
    user: DeveloperLoginSchema,
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, user.email, user.password, None)
    if not user:
        raise HTTPException(status_code=400, detail='Invalid credentials')
    
    access_token = create_access_token(data={"sub": user.id})
    refresh_token = create_refresh_token(data={"sub": user.id})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.get("/get-user/", response_model=GetDeveloperDetailsSchema)
def get_user_endpoint(
    current_user: User = Depends(get_current_user)
):
    return current_user

@router.post("/token/refresh/")
async def refresh_token_endpoint(
    request: Request,
    db: Session = Depends(get_db),
):
    data = await request.json()
    token = data.get("refresh_token")
    if not token:
        raise HTTPException(status_code=400, detail="Token is required")

    payload = decode_refresh_token(token)
    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid token or expired token",
        )
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid token or expired token",
        )

    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    access_token = create_access_token(data={"sub": user.id})
    return {
        "access_token": access_token,
        "refresh_token": token,
        "token_type": "bearer"
    }