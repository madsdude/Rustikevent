from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Field, Session, create_engine, select
from pydantic import BaseModel, field_validator
from passlib.context import CryptContext
from typing import Optional, Any
import datetime, os, re, jwt

# ---- Config ----
DB_URL      = os.environ.get("DB_URL", "sqlite:////data/events.db")
SECRET_KEY  = os.environ.get("SECRET_KEY", "dev-secret-change-me")
ADMIN_USER  = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS  = os.environ.get("ADMIN_PASS", "changeme")
ALGORITHM   = "HS256"
TOKEN_HOURS = 12

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})

app = FastAPI(title="RustikEvent API", version="0.3")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # låses evt. ned senere
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- DB Models ----
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str      = Field(index=True, unique=True)
    password_hash: str

class Event(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    date: str                       # YYYY-MM-DD
    doors: Optional[str] = None     # HH:MM
    start: Optional[str] = None     # HH:MM
    price: Optional[str] = None
    age: Optional[str] = "18+"
    location: Optional[str] = "Rustik Event, Randers"
    poster_url: Optional[str] = None
    facebook_url: Optional[str] = None
    tags: Optional[str] = None      # comma-separated
    status: Optional[str] = "announced"
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

def create_access_token(data: dict, hours: int = TOKEN_HOURS) -> str:
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=hours)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(request: Request, session: Session = Depends(get_session)) -> User:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing Bearer token")
    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(401, "Invalid token")
    username: Optional[str] = payload.get("sub")
    if not username:
        raise HTTPException(401, "Invalid token")
    user = session.exec(select(User).where(User.username == username)).first()
    if not user:
        raise HTTPException(401, "User not found")
    return user

def normalize_date(s: str) -> str:
    if not s:
        return s
    s = str(s)
    # DD-MM-YYYY -> YYYY-MM-DD
    if re.match(r'^\d{2}-\d{2}-\d{4}$', s):
        d, m, y = s.split('-')
        return f"{y}-{m}-{d}"
    return s

def normalize_tags(v: Any) -> Optional[str]:
    if v is None or v == "":
        return None
    if isinstance(v, list):
        return ",".join([str(x).strip() for x in v if str(x).strip()])
    return str(v)

# ---- Startup (DB + admin sync fra .env) ----
@app.on_event("startup")
def on_startup():
    os.makedirs("/data", exist_ok=True)
    SQLModel.metadata.create_all(engine)

    admin_user = os.getenv("ADMIN_USER", ADMIN_USER)
    admin_pass = os.getenv("ADMIN_PASS", ADMIN_PASS)
    if not admin_user or not admin_pass:
        return

    with Session(engine) as s:
        u = s.exec(select(User).where(User.username == admin_user)).first()
        if u:
            u.password_hash = hash_password(admin_pass)  # sync ved hver start
            s.add(u)
        else:
            s.add(User(username=admin_user, password_hash=hash_password(admin_pass)))
        s.commit()

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
@app.get("/api/events")
def list_events(session: Session = Depends(get_session)):
    rows = session.exec(select(Event).order_by(Event.date)).all()
    return [e.model_dump() for e in rows]

# ---- Admin DTOs ----
class EventCreate(BaseModel):
    title: str
    date: str
    doors: Optional[str] = None
    start: Optional[str] = None
    price: Optional[str] = None
    age: Optional[str] = "18+"
    location: Optional[str] = "Rustik Event, Randers"
    poster_url: Optional[str] = None
    facebook_url: Optional[str] = None
    tags: Optional[list[str] | str] = None
    status: Optional[str] = "announced"
    highlight: bool = False
    description: Optional[str] = None

    @field_validator('date', mode='before')
    @classmethod
    def _date(cls, v): return normalize_date(v)

    @field_validator('tags', mode='before')
    @classmethod
    def _tags(cls, v): return normalize_tags(v)

class EventUpdate(BaseModel):
    title: Optional[str] = None
    date: Optional[str] = None
    doors: Optional[str] = None
    start: Optional[str] = None
    price: Optional[str] = None
    age: Optional[str] = None
    location: Optional[str] = None
    poster_url: Optional[str] = None
    facebook_url: Optional[str] = None
    tags: Optional[list[str] | str] = None
    status: Optional[str] = None
    highlight: Optional[bool] = None
    description: Optional[str] = None

    @field_validator('date', mode='before')
    @classmethod
    def _date(cls, v): return normalize_date(v)

    @field_validator('tags', mode='before')
    @classmethod
    def _tags(cls, v): return normalize_tags(v)

# ---- Admin Events (kræver Bearer token) ----
@app.post("/api/events")
def create_event(payload: EventCreate, _: User = Depends(get_current_user), session: Session = Depends(get_session)):
    e = Event(**payload.model_dump())
    session.add(e); session.commit(); session.refresh(e)
    return e.model_dump()

@app.put("/api/events/{event_id}")
def update_event(event_id: int, payload: EventUpdate, _: User = Depends(get_current_user), session: Session = Depends(get_session)):
    ev = session.get(Event, event_id)
    if not ev: raise HTTPException(404, "Event ikke fundet")
    data = payload.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(ev, k, v)
    session.add(ev); session.commit(); session.refresh(ev)
    return ev.model_dump()

@app.delete("/api/events/{event_id}")
def delete_event(event_id: int, _: User = Depends(get_current_user), session: Session = Depends(get_session)):
    ev = session.get(Event, event_id)
    if not ev: raise HTTPException(404, "Event ikke fundet")
    session.delete(ev); session.commit()
    return {"deleted": event_id}
