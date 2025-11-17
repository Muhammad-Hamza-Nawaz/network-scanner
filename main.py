from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import uvicorn

from scanner import run_scan
from firewall import Firewall, Rule, Packet

app = FastAPI(title="Network Scanner & Firewall Visualizer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the static HTML from the templates folder
app.mount("/static", StaticFiles(directory="static"), name="static")

firewall = Firewall()
# enable persistence to file
try:
    firewall.enable_persistence('firewall_rules.json')
except Exception:
    # if file system not writable or other error, continue without persistence
    pass


class ScanRequest(BaseModel):
    target: str
    scan_type: Optional[str] = "tcp"
    ports: Optional[str] = "1-1024"


class RuleRequest(BaseModel):
    action: str  # allow or deny
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    priority: Optional[int] = 100


class PacketRequest(BaseModel):
    src_ip: str
    dst_ip: str
    port: int
    protocol: str


@app.get("/", response_class=HTMLResponse)
async def index():
    with open("templates/index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.post("/api/scan")
async def api_scan(req: ScanRequest):
    try:
        results = run_scan(req.target, req.scan_type or "tcp", req.ports or "1-1024")
        return {"target": req.target, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rules")
async def add_rule(r: RuleRequest):
    rule = Rule(
        action=r.action,
        src_ip=r.src_ip,
        dst_ip=r.dst_ip,
        port=r.port,
        protocol=r.protocol,
        priority=r.priority,
    )
    rule = firewall.add_rule(rule)
    return {"status": "ok", "rule": rule.dict()}


@app.get("/api/rules")
async def list_rules():
    return {"rules": [r.dict() for r in firewall.list_rules()]}


@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: int):
    ok = firewall.remove_rule(rule_id)
    if ok:
        return {"status": "ok", "deleted": rule_id}
    else:
        raise HTTPException(status_code=404, detail="rule not found")


@app.put("/api/rules/{rule_id}")
async def update_rule(rule_id: int, r: RuleRequest):
    updated = firewall.update_rule(
        rule_id,
        action=r.action,
        src_ip=r.src_ip,
        dst_ip=r.dst_ip,
        port=r.port,
        protocol=r.protocol,
        priority=r.priority,
    )
    if updated:
        return {"status": "ok", "rule": updated.dict()}
    else:
        raise HTTPException(status_code=404, detail="rule not found")


@app.post("/api/evaluate")
async def evaluate_packet(p: PacketRequest):
    packet = Packet(src_ip=p.src_ip, dst_ip=p.dst_ip, port=p.port, protocol=p.protocol)
    action = firewall.evaluate(packet)
    return {"action": action}


@app.get('/api/firewall')
async def get_firewall():
    return {"default_action": firewall.default_action}


@app.post('/api/firewall/default')
async def set_firewall_default(body: dict):
    action = body.get('default_action')
    if action not in ('allow', 'deny'):
        raise HTTPException(status_code=400, detail='invalid action')
    firewall.set_default_action(action)
    return {"status": "ok", "default_action": firewall.default_action}


@app.post('/api/rules/clear')
async def clear_rules():
    firewall.clear_rules()
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
