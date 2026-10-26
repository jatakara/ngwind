"""RemedyOps AI v0.2: localhost-only sandbox demo, NOT a production SSH agent."""
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Integer, String, Text, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from pathlib import Path
from datetime import datetime, timezone
from remediation_safety import restore_backup_after_verification_failure
from recovery_journal import (
    RecoveryJournalError, record_intent, record_outcome,
    unresolved_changes, write_durable_backup,
)
import os, json, hashlib, uuid, threading

app = FastAPI(title="RemedyOps AI", version="0.2")
URL = os.getenv("DATABASE_URL", "sqlite:///./remedyops.db")
engine = create_engine(URL, connect_args={"check_same_thread": False} if URL.startswith("sqlite") else {})
class Base(DeclarativeBase): pass
class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(120))
class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action: Mapped[str] = mapped_column(String(80))
    detail: Mapped[str] = mapped_column(Text)
Base.metadata.create_all(engine)

class AssetIn(BaseModel):
    name: str = Field(min_length=1,max_length=120)
    host: str = Field(min_length=1,max_length=255,pattern=r"^[a-zA-Z0-9.:-]+$")
    port: int = Field(default=22,ge=1,le=65535)
    username: str = Field(min_length=1,max_length=120,pattern=r"^[a-zA-Z_][a-zA-Z0-9_.-]*$")
class PlanIn(BaseModel):
    finding_ids: list[str] = Field(min_length=1,max_length=20)
class ApplyIn(BaseModel):
    plan_id: str
    approved: bool = False
class RollbackIn(BaseModel):
    change_ids: list[str] = Field(min_length=1,max_length=20)
    approved: bool = False

ROOT = Path(__file__).resolve().parent
TARGET = ROOT / "demo_target"
STATE = ROOT / ".state"
TARGET.mkdir(exist_ok=True)
STATE.mkdir(exist_ok=True)
LOCK = threading.RLock()
RULES = {
    "LOG-001": ("logging.conf", "audit_enabled", "yes", "low"),
    "PERM-001": ("permissions.conf", "temp_mode", "0750", "low"),
    "SSH-001": ("ssh.conf", "password_auth", "no", "high"),
}
def event(action, detail):
    with Session(engine) as db:
        db.add(Event(action=action,detail=json.dumps(detail)));db.commit()
def sha(data): return hashlib.sha256(data).hexdigest()
def file_for(rule):
    p=(TARGET/rule[0]).resolve()
    if not p.is_relative_to(TARGET.resolve()) or p.is_symlink(): raise HTTPException(400,"Unsafe path")
    return p
def data_file(prefix, ident): return STATE / (prefix+"-"+ident+".json")
def save(prefix,ident,obj):
    p=data_file(prefix,ident);tmp=p.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj,indent=2),encoding="utf-8");os.replace(tmp,p)
def load(prefix,ident):
    if not ident.isalnum(): raise HTTPException(400,"Invalid ID")
    p=data_file(prefix,ident)
    if not p.exists():raise HTTPException(404,"Record not found")
    return json.loads(p.read_text(encoding="utf-8"))
def config(data):
    return dict(line.split("=",1) for line in data.decode().splitlines() if "=" in line)
def change(data,key,value):
    rows=data.decode().splitlines()
    rows=[key+"="+value if "=" in x and x.split("=",1)[0]==key else x for x in rows]
    if not any(x.startswith(key+"=") for x in rows):rows.append(key+"="+value)
    return ("\n".join(rows)+"\n").encode()
for fid,(name,key,desired,risk) in RULES.items():
    p=TARGET/name
    if not p.exists():p.write_text(key+"="+({"LOG-001":"no","PERM-001":"0777","SSH-001":"yes"}[fid])+"\n")

@app.get("/",response_class=HTMLResponse)
def home():return (ROOT/"index.html").read_text(encoding="utf-8")
@app.get("/api/dashboard")
def dashboard():
    with Session(engine) as db:
        return {"assets":db.scalar(select(func.count()).select_from(Asset)),
                "events":db.scalar(select(func.count()).select_from(Event))}
@app.get("/api/assets")
def assets():
    with Session(engine) as db:
        return [{"id":a.id,"name":a.name,"host":a.host,"port":a.port,"username":a.username}
                for a in db.scalars(select(Asset).order_by(Asset.id.desc()))]
@app.post("/api/assets",status_code=201)
def add_asset(item:AssetIn):
    with Session(engine) as db:
        a=Asset(**item.model_dump());db.add(a);db.commit();db.refresh(a)
        result={"id":a.id,**item.model_dump()}
    event("asset.created",{"id":result["id"]});return result
@app.post("/api/plan")
def plan(req:PlanIn):
    with LOCK:
        pid=uuid.uuid4().hex;entries=[]
        for fid in dict.fromkeys(req.finding_ids):
            if fid not in RULES:
                entries.append({"finding_id":fid,"status":"unsupported"});continue
            rule=RULES[fid];p=file_for(rule);before=p.read_bytes()
            entries.append({"finding_id":fid,"status":"planned","before_hash":sha(before),
                            "risk":rule[3],"desired":rule[2]})
        obj={"plan_id":pid,"status":"planned","entries":entries};save("plan",pid,obj)
        event("plan.created",{"id":pid});return obj
@app.post("/api/apply")
def apply(req:ApplyIn):
    if not req.approved:raise HTTPException(400,"Approval required")
    with LOCK:
        obj=load("plan",req.plan_id)
        # Fail closed after a crash or failed restoration. Never auto-recover.
        try:
            pending=unresolved_changes(STATE)
        except (OSError, RecoveryJournalError) as exc:
            raise HTTPException(503,"Recovery journal unreadable; remediation disabled") from exc
        if pending:
            raise HTTPException(409,"Unresolved remediation requires manual recovery")
        if obj["status"]!="planned":raise HTTPException(409,"Already processed")
        changes=[]
        for entry in obj["entries"]:
            if entry["status"]!="planned":continue
            fid=entry["finding_id"];rule=RULES[fid]
            if rule[3]!="low":
                entry["status"]="blocked_high_risk";continue
            p=file_for(rule);before=p.read_bytes()
            if sha(before)!=entry["before_hash"]:
                entry["status"]="conflict";continue
            after=change(before,rule[1],rule[2]);cid=uuid.uuid4().hex
            # Persist the backup and intent before changing any target bytes.
            backup_path=STATE/("backup-"+cid+".bin")
            try:
                write_durable_backup(backup_path,before)
                record_intent(STATE,cid,fid,sha(before),sha(after))
            except (OSError, RecoveryJournalError) as exc:
                raise HTTPException(503,"Cannot persist remediation intent") from exc
            p.write_bytes(after)
            verified=config(p.read_bytes()).get(rule[1])==rule[2]
            status=("applied" if verified else
                    restore_backup_after_verification_failure(
                        p, backup_path, sha(before)))
            rec={"change_id":cid,"finding_id":fid,"before_hash":sha(before),
                 "after_hash":sha(after),"status":status}
            save("change",cid,rec)
            # Finalize only after the change record is persisted. An interrupted
            # finalization leaves an unresolved intent and blocks future apply.
            record_outcome(STATE,cid,status)
            changes.append(rec);entry["status"]=rec["status"]
        obj["status"]="processed";obj["changes"]=changes;save("plan",req.plan_id,obj)
        event("plan.applied",{"id":req.plan_id,"changes":len(changes)});return obj
@app.get("/api/changes")
def changes():
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(STATE.glob("change-*.json"))]
@app.post("/api/rollback")
def rollback(req:RollbackIn):
    if not req.approved:raise HTTPException(400,"Approval required")
    if len(req.change_ids)!=len(set(req.change_ids)):raise HTTPException(400,"Duplicate changes")
    with LOCK:
        records=[load("change",cid) for cid in req.change_ids]
        names=[RULES[c["finding_id"]][0] for c in records]
        if len(names)!=len(set(names)):raise HTTPException(409,"Overlapping files: group recovery required")
        results=[]
        for rec in records:
            cid=rec["change_id"]
            if rec["status"]!="applied":
                results.append({"id":cid,"status":"not_eligible"});continue
            p=file_for(RULES[rec["finding_id"]]);current=p.read_bytes()
            if sha(current)!=rec["after_hash"]:
                results.append({"id":cid,"status":"conflict"});continue
            backup=(STATE/("backup-"+cid+".bin")).read_bytes()
            if sha(backup)!=rec["before_hash"]:raise HTTPException(409,"Backup integrity failure")
            p.write_bytes(backup);ok=sha(p.read_bytes())==rec["before_hash"]
            rec["status"]="rolled_back" if ok else "rollback_failed"
            save("change",cid,rec);results.append({"id":cid,"status":rec["status"]})
        event("rollback.executed",{"results":results});return {"results":results}
@app.get("/api/audit")
def audit():
    with Session(engine) as db:
        return [{"action":e.action,"detail":json.loads(e.detail)} for e in db.scalars(select(Event).order_by(Event.id.desc()).limit(100))]

# v0.3: authenticated read-only SSH diagnostic endpoint.
# Requires an explicitly configured token; never accepts SSH secrets in API payload.
from fastapi import Request
from fastapi.responses import JSONResponse
from ssh_diagnostics import Diagnostic, diagnose
import hmac

@app.middleware("http")
async def api_guard(request: Request, call_next):
    token=os.environ.get("REMEDYOPS_API_TOKEN","")
    # Without a token the service is restricted to localhost clients only.
    # For remote access set REMEDYOPS_API_TOKEN and use TLS reverse proxy.
    peer=request.client.host if request.client else ""
    if not token and peer not in ("127.0.0.1","::1","testclient"):
        return JSONResponse({"detail":"Token not configured: localhost only"},status_code=403)
    if token and not hmac.compare_digest(request.headers.get("X-API-Token",""),token):
        return JSONResponse({"detail":"Unauthorized"},status_code=401)
    return await call_next(request)

class DiagnosticIn(BaseModel):
    asset_id: int = Field(ge=1)

@app.post("/api/diagnose")
def diagnose_asset(req:DiagnosticIn):
    if os.environ.get("REMEDYOPS_ENABLE_SSH_DIAGNOSTICS")!="true":
        raise HTTPException(403,"SSH diagnostics are disabled")
    with Session(engine) as db:
        asset=db.get(Asset,req.asset_id)
        if not asset:raise HTTPException(404,"Asset not found")
        # The private key and host-key pin are provisioned on the controller.
        # They are not transmitted by the browser or stored in the DB.
        key_path=os.environ.get("REMEDYOPS_SSH_KEY_PATH","")
        known_hosts=os.environ.get("REMEDYOPS_KNOWN_HOSTS_PATH","")
        d=Diagnostic(asset.host,asset.port,asset.username,key_path,known_hosts)
    try:
        result=diagnose(d)
    except Exception as exc:
        event("diagnostic.failed",{"asset_id":req.asset_id,"type":type(exc).__name__})
        raise HTTPException(502,"SSH diagnostic failed; check controller logs") from exc
    event("diagnostic.completed",{"asset_id":req.asset_id,"checks":list(result)})
    return {"asset_id":req.asset_id,"mode":"read_only","checks":result}
