from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi import FastAPI, HTTPException, Depends
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
# ensure unique id
if any(e.id == event.id for e in events):
event.id = _next_id(events)
events.append(event)
_save(events)
return event


@app.put("/api/events/{event_id}", response_model=Event)
def update_event(event_id: int, event: Event, _: bool = Depends(require_admin)):
events = _load()
for i, e in enumerate(events):
if e.id == event_id:
events[i] = event
_save(events)
return event
raise HTTPException(404, "Event not found")


@app.delete("/api/events/{event_id}")
def delete_event(event_id: int, _: bool = Depends(require_admin)):
events = _load()
new_events = [e for e in events if e.id != event_id]
if len(new_events) == len(events):
raise HTTPException(404, "Event not found")
_save(new_events)
return {"deleted": event_id}


# Seed file if missing
if not os.path.exists(EVENTS_FILE):
_save([])
