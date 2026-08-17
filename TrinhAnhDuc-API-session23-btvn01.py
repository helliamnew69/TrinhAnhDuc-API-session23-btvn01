from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError, ExpiredSignatureError


app = FastAPI()

SECRET_KEY = "training-secret-key"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

USERS = {
    "alice": {
        "username": "alice",
        "full_name": "Alice Nguyen",
        "role": "user",
        "is_active": True,
    },
    "bob": {
        "username": "bob",
        "full_name": "Bob Tran",
        "role": "user",
        "is_active": False,
    },
}


@app.get("/issue-token/{username}")
def issue_token(username: str, expired: bool = False):
    if username not in USERS:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=-5 if expired else 30
    )

    token = jwt.encode(
        {
            "sub": username,
            "exp": expires_at,
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
    }


def get_current_user(
    token: str = Depends(oauth2_scheme)
):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={
                "WWW-Authenticate": "Bearer"
            }
        )

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={
                "WWW-Authenticate": "Bearer"
            }
        )

    username = payload.get("sub")

    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={
                "WWW-Authenticate": "Bearer"
            }
        )

    user = USERS.get(username)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={
                "WWW-Authenticate": "Bearer"
            }
        )

    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    return user


@app.get("/users/me")
def read_current_user(
    current_user: dict = Depends(get_current_user)
):
    return current_user