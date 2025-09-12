from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Field, Session, create_engine, select
from typing import Optional, List
from passlib.context import CryptContext
import os, datetime, jwt

# ---- Config ----
DB_URL = os.environ.get("DB_URL", "sqlite:////data/events.db")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "changeme")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 12

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})

app = FastAPI(title="RustikEvent API", version="0.2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Models ----
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str

class Event(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    date: str  # YYYY-MM-DD
    doors: Optional[str] = None  # HH:MM
    start: Optional[str] = None  # HH:MM
    price: Optional[str] = None
    age: Optional[str] = "18+"
    location: Optional[str] = "Rustik Event, Randers"
    poster_url: Optional[str] = None
    facebook_url: Optional[str] = None
    tags: Optional[str] = None  # comma-separated
    status: Optional[str] = "announced"  # announced|soldout|cancelled
    highlight: bool = False
    description: Optional[str] = None

# ---- Helpers ----
def get_session():
    with Session(engine) as session:
        yield session

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)

def create_access_token(data: dict, expires_delta: datetime.timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta or datetime.timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(lambda authorization: authorization),
                     session: Session = Depends(get_session)):
    # FastAPI passes the whole header string; robust handling below
    import inspect
    from fastapi import Request
    frame = inspect.currentframe()
    # Try to fetch Authorization header from context request
    request: Request | None = None
    while frame:
        for name, val in frame.f_locals.items():
            if isinstance(val, Request):
                request = val
                break
        frame = frame.f_back
    if not request:
        raise HTTPException(401, "Unauthorized")
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing Bearer token")
    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(401, "Invalid token")
    username: str = payload.get("sub")
    if not username:
        raise HTTPException(401, "Invalid token")
    user = session.exec(select(User).where(User.username == username)).first()
    if not user:
        raise HTTPException(401, "User not found")
    return user

# ---- Startup ----
@app.on_event("startup")
def on_startup():
    os.makedirs("/data", exist_ok=True)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        # Seed admin if not exists
        if not session.exec(select(User).where(User.username == ADMIN_USER)).first():
            session.add(User(username=ADMIN_USER, password_hash=hash_password(ADMIN_PASS)))
            session.commit()

# ---- Health ----
@app.get("/health")
def health():
    return {"ok": True, "ts": datetime.datetime.utcnow().isoformat()}

# ---- Auth ----
@app.post("/api/login")
def login(form: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == form.username)).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(401, "Forkert brugernavn/kode")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer", "username": user.username}

# ---- Public Events ----
@app.get("/api/events", response_model=List[Event])
def list_events(session: Session = Depends(get_session)):
    return session.exec(select(Event).order_by(Event.date)).all()

# ---- Admin Events ----
@app.post("/api/events", response_model=Event)
def create_event(event: Event, _: User = Depends(get_current_user), session: Session = Depends(get_session)):
    event.id = None  # autoincrement
    session.add(event)
    session.commit()
    session.refresh(event)
    return event

@app.put("/api/events/{event_id}", response_model=Event)
def update_event(event_id: int, data: Event, _: User = Depends(get_current_user), session: Session = Depends(get_session)):
    ev = session.get(Event, event_id)
    if not ev: raise HTTPException(404, "Event ikke fundet")
    for k, v in data.dict().items():
        if k == "id": continue
        setattr(ev, k, v)
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev

@app.delete("/api/events/{event_id}")
def delete_event(event_id: int, _: User = Depends(get_current_user), session: Session = Depends(get_session)):
    ev = session.get(Event, event_id)
    if not ev: raise HTTPException(404, "Event ikke fundet")
    session.delete(ev)
    session.commit()
    return {"deleted": event_id}
