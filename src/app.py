"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


class User(BaseModel):
    id: str
    name: str
    email: str
    role: str = "student"


class UserRegisterRequest(BaseModel):
    name: str
    email: str
    password: str
    role: Optional[str] = "student"


class UserLoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    email: str
    token: str
    new_password: str


app = FastAPI(
    title="Mergington High School API",
    description="API for viewing and signing up for extracurricular activities",
)

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(Path(__file__).parent, "static")),
    name="static",
)

DATA_DIR = current_dir / "data"
DATA_DIR.mkdir(exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"

security = HTTPBearer(auto_error=False)

auth_tokens: Dict[str, str] = {}
reset_tokens: Dict[str, str] = {}


def ensure_users_file() -> None:
    if not USERS_FILE.exists():
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)


def load_users() -> List[Dict[str, Any]]:
    ensure_users_file()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def save_users(users: List[Dict[str, Any]]) -> None:
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed


def find_user(email: str) -> Optional[Dict[str, Any]]:
    users = load_users()
    normalized = email.strip().lower()
    return next((user for user in users if user["email"] == normalized), None)


def sanitize_user(user: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
    }


def create_access_token(email: str) -> str:
    token = secrets.token_urlsafe(32)
    auth_tokens[token] = email.lower()
    return token


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing or invalid",
        )

    user_email = auth_tokens.get(credentials.credentials)
    if not user_email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
        )

    user = find_user(user_email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user


def get_current_user_optional(
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> Optional[Dict[str, Any]]:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    email = auth_tokens.get(token)
    if not email:
        return None
    return find_user(email)


def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"],
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"],
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"],
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"],
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"],
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"],
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"],
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"],
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"],
    },
}


@app.on_event("startup")
def startup():
    ensure_users_file()


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/auth/register", response_model=TokenResponse)
def register(request: UserRegisterRequest):
    normalized_email = request.email.strip().lower()
    if find_user(normalized_email) is not None:
        raise HTTPException(status_code=400, detail="A user with that email already exists")

    if request.role not in {"student", "admin"}:
        raise HTTPException(status_code=400, detail="Role must be 'student' or 'admin'")

    users = load_users()
    if request.role == "admin" and len(users) > 0:
        raise HTTPException(
            status_code=403,
            detail="Admin registration is reserved for the first user or existing admins",
        )

    user = {
        "id": secrets.token_hex(8),
        "name": request.name.strip(),
        "email": normalized_email,
        "role": request.role,
        "hashed_password": hash_password(request.password),
    }
    users.append(user)
    save_users(users)
    token = create_access_token(normalized_email)
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(request: UserLoginRequest):
    user = find_user(request.email)
    if user is None or not verify_password(request.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(user["email"])
    return TokenResponse(access_token=token)


@app.get("/users/me", response_model=User)
def get_current_user_profile(user: Dict[str, Any] = Depends(get_current_user)):
    return User(**sanitize_user(user))


@app.put("/users/me", response_model=User)
def update_profile(
    request: UpdateProfileRequest,
    user: Dict[str, Any] = Depends(get_current_user),
):
    users = load_users()
    stored = next((u for u in users if u["email"] == user["email"]), None)
    if stored is None:
        raise HTTPException(status_code=404, detail="User not found")

    if request.name:
        stored["name"] = request.name.strip()

    if request.new_password:
        if not request.current_password or not verify_password(request.current_password, stored["hashed_password"]):
            raise HTTPException(status_code=400, detail="Current password is required to change password")
        stored["hashed_password"] = hash_password(request.new_password)

    save_users(users)
    return User(**sanitize_user(stored))


@app.post("/auth/forgot-password")
def forgot_password(request: ForgotPasswordRequest):
    user = find_user(request.email)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    token = secrets.token_urlsafe(24)
    reset_tokens[token] = user["email"]
    return {"message": "Password reset token generated", "reset_token": token}


@app.post("/auth/reset-password")
def reset_password(request: ResetPasswordRequest):
    email = reset_tokens.get(request.token)
    if email is None or email != request.email.strip().lower():
        raise HTTPException(status_code=400, detail="Reset token is invalid or expired")

    users = load_users()
    user = next((u for u in users if u["email"] == request.email.strip().lower()), None)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    user["hashed_password"] = hash_password(request.new_password)
    save_users(users)
    del reset_tokens[request.token]
    return {"message": "Password has been reset"}


@app.get("/users", response_model=List[User])
def list_users(_: Dict[str, Any] = Depends(require_admin)):
    users = load_users()
    return [User(**sanitize_user(user)) for user in users]


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: Optional[str] = None,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional),
):
    if current_user is not None:
        email = current_user["email"]

    if not email:
        raise HTTPException(status_code=400, detail="Email or authentication token required")

    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activity = activities[activity_name]
    if email in activity["participants"]:
        raise HTTPException(status_code=400, detail="Student is already signed up")

    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: Optional[str] = None,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional),
):
    if current_user is not None:
        email = current_user["email"]

    if not email:
        raise HTTPException(status_code=400, detail="Email or authentication token required")

    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activity = activities[activity_name]
    if email not in activity["participants"]:
        raise HTTPException(status_code=400, detail="Student is not signed up for this activity")

    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
