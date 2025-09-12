from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from typing import List, Optional
import json, os, threading, secrets, datetime


app = FastAPI(title="RustikEvent API", version="0.1")
security = HTTPBasic()
lock = threading.Lock()


EVENTS_FILE = os.environ.get("EVENTS_FILE", "/data/events.json")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "changeme")


app.add_middleware(
CORSMiddleware,
allow_origins=["*"],
allow_credentials=True,
allow_methods=["*"]
,allow_headers=["*"]
)


class Event(BaseModel):
id: int = Field(..., description="Auto-increment id")
title: str
date: str # YYYY-MM-DD
doors: Optional[str] = None # HH:MM
start: Optional[str] = None # HH:MM
price: Optional[str] = None
age: Optional[str] = "18+"
location: Optional[str] = "Rustik Event, Randers"
poster_url: Optional[str] = None
facebook_url: Optional[str] = None
tags: List[str] = []
status: Optional[str] = "announced" # announced|soldout|cancelled
highlight: bool = False
description: Optional[str] = None




def _load() -> List[Event]:
if not os.path.exists(EVENTS_FILE):
return []
with lock:
with open(EVENTS_FILE, "r", encoding="utf-8") as f:
data = json.load(f)
return [Event(**e) for e in data]




def _save(events: List[Event]):
with lock:
os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
with open(EVENTS_FILE, "w", encoding="utf-8") as f:
json.dump([e.model_json_schema(mode='serialization') and e.model_dump() for e in events], f, ensure_ascii=False, indent=2)




def _next_id(events: List[Event]) -> int:
return (max([e.id for e in events]) + 1) if events else 1




def require_admin(credentials: HTTPBasicCredentials = Depends(security)):
correct_user = secrets.compare_digest(credentials.username, ADMIN_USER)
correct_pass = secrets.compare_digest(credentials.password, ADMIN_PASS)
if not (correct_user and correct_pass):
raise HTTPException(status_code=401, detail="Unauthorized")
return True


@app.get("/health")
def health():
return {"ok": True, "ts": datetime.datetime.utcnow().isoformat()}


@app.get("/api/events", response_model=List[Event])
def list_events():
events = _load()
# sort by date ascending
events.sort(key=lambda e: e.date)
return events


@app.post("/api/events", response_model=Event)
def create_event(event: Event, _: bool = Depends(require_admin)):
events = _load()
if event.id == 0:
event.id = _next_id(events)
_save([])
