import os
import hmac
import secrets
from datetime import datetime, timezone
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(title="Cutie Remote Server", version="1.1.0")
API_KEY = os.getenv("CUTIE_API_KEY", "")
PAIRING_CODE = os.getenv("CUTIE_PAIRING_CODE", "")
FEATURES = {
    "remote_phone_monitor": False,
    "remote_camera": False,
    "remote_microphone": False,
    "sms_monitor": False,
    "whatsapp_automation": False,
    "remote_build": False,
}
commands: list[dict] = []


def require_admin(key: str | None):
    if not API_KEY:
        raise HTTPException(503, "Server admin key is not configured")
    if not key or not hmac.compare_digest(key, API_KEY):
        raise HTTPException(401, "Invalid or missing API key")


class PairRequest(BaseModel):
    device_name: str = Field(min_length=1, max_length=80)
    pairing_code: str = Field(min_length=8, max_length=200)


class CommandRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=100)
    task: Literal["status", "scan", "build"]


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(DASHBOARD_HTML)


@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.get("/v1/admin/status")
def admin_status(x_api_key: str | None = Header(default=None)):
    require_admin(x_api_key)
    return {"server": "online", "version": app.version, "command_requests": len(commands)}


@app.get("/v1/features")
def get_features(x_api_key: str | None = Header(default=None)):
    require_admin(x_api_key)
    return {"features": FEATURES}


@app.post("/v1/device/pair")
def pair_device(body: PairRequest, x_api_key: str | None = Header(default=None)):
    require_admin(x_api_key)
    if not PAIRING_CODE or not hmac.compare_digest(body.pairing_code, PAIRING_CODE):
        raise HTTPException(403, "Invalid pairing code")
    # Deliberately does not issue a device token or persist pairing yet.
    return {"accepted": True, "device_name": body.device_name,
            "message": "Pairing code accepted for prototype; persistent pairing is not implemented"}


@app.post("/v1/commands")
def submit_command(body: CommandRequest, x_api_key: str | None = Header(default=None)):
    require_admin(x_api_key)
    if len(commands) >= 100:
        raise HTTPException(429, "Demo command queue is full")
    item = {"id": secrets.token_urlsafe(8), "device_id": body.device_id,
            "task": body.task, "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat()}
    commands.append(item)
    return {"accepted": True, "command": item,
            "message": "Recorded only; no device is connected to execute it"}


@app.get("/v1/commands")
def list_commands(x_api_key: str | None = Header(default=None)):
    require_admin(x_api_key)
    return {"commands": commands}


DASHBOARD_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cutie Remote</title>
<style>
:root{color-scheme:dark;--bg:#08111f;--panel:#111f33;--line:#263a55;--text:#eef5ff;--muted:#9fb1ca;--accent:#70d6ff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 0,#173458 0,transparent 40%),var(--bg);color:var(--text);font:16px system-ui,sans-serif}.wrap{max-width:850px;margin:auto;padding:24px 16px 48px}.brand{display:flex;align-items:center;gap:12px;margin-bottom:24px}.orb{width:46px;height:46px;border-radius:50%;background:radial-gradient(circle at 35% 30%,#fff,#70d6ff 25%,#476bff 60%,#18264d);box-shadow:0 0 24px #70d6ff55}.brand h1{margin:0;font-size:25px}.muted{color:var(--muted)}.card{background:#111f33ee;border:1px solid var(--line);border-radius:18px;padding:18px;margin:14px 0;box-shadow:0 10px 30px #0002}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.label{display:block;color:var(--muted);font-size:13px;margin:10px 0 6px}input{width:100%;padding:12px;border:1px solid var(--line);border-radius:10px;background:#081525;color:var(--text)}button{border:0;border-radius:10px;background:var(--accent);color:#071321;font-weight:700;padding:12px 16px;cursor:pointer;margin:8px 6px 0 0}button.secondary{background:#233750;color:var(--text);border:1px solid var(--line)}.status{font-weight:700}.good{color:#6ee7b7}.bad{color:#fda4af}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#07111f;border-radius:10px;padding:12px;color:#cce7ff;min-height:48px}.small{font-size:13px}.hidden{display:none}h2{font-size:18px;margin:0 0 8px}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:4px 9px;color:var(--muted);font-size:12px}
</style></head><body><main class="wrap"><header class="brand"><div class="orb"></div><div><h1>Cutie Remote</h1><div class="muted">Private server dashboard · prototype</div></div></header>
<section class="card"><h2>Admin connection</h2><p class="muted small">Enter the CUTIE_API_KEY configured in Render Environment. The key is kept only in this page's memory and is not saved.</p><label class="label" for="key">Admin API key</label><input id="key" type="password" autocomplete="off" placeholder="Paste your secret key"><button id="connect">Connect & check status</button><button id="clear" class="secondary">Clear key</button><p id="connection" class="status muted">Not connected</p></section>
<section class="grid"><div class="card"><h2>Server status</h2><p id="serverState" class="status muted">Not checked</p><button class="secondary" id="health">Check public health</button><pre id="healthOut">Waiting</pre></div><div class="card"><h2>Feature flags</h2><p class="muted small">Sensitive phone features stay disabled in this prototype.</p><pre id="featuresOut">Admin connection required</pre></div></section>
<section class="card"><h2>Command history</h2><p class="muted small">This prototype records allowed task requests only. It does not execute commands on a phone.</p><button id="history" class="secondary">Refresh history</button><pre id="historyOut">Admin connection required</pre></section>
<section class="card"><h2>Device pairing status</h2><p class="muted">Pairing API currently validates a code but does not persist devices or issue device tokens. Do not treat a device as paired yet.</p><span class="pill">Persistent pairing not implemented</span></section>
<p class="muted small">Security note: use only over HTTPS. Never share your API key or place it in a public repository. This dashboard does not control camera, microphone, SMS, WhatsApp, or system settings.</p></main>
<script>
const base=location.origin;const $=id=>document.getElementById(id);let key='';function headers(){return {'X-API-Key':key}}async function req(path,opts={}){const r=await fetch(base+path,{...opts,headers:{...(opts.headers||{}),...(key?headers():{})}});let data;try{data=await r.json()}catch{data={detail:await r.text()}}if(!r.ok)throw Error(`${r.status}: ${data.detail||JSON.stringify(data)}`);return data}
$('connect').onclick=async()=>{key=$('key').value.trim();if(!key){$('connection').textContent='Enter your API key first';return}try{const s=await req('/v1/admin/status');$('connection').textContent='Connected · server '+s.server;$('connection').className='status good';$('serverState').textContent='Online · v'+s.version;$('serverState').className='status good';$('featuresOut').textContent=JSON.stringify(await req('/v1/features'),null,2);$('historyOut').textContent=JSON.stringify(await req('/v1/commands'),null,2)}catch(e){$('connection').textContent='Connection failed: '+e.message;$('connection').className='status bad';key=''}};
$('clear').onclick=()=>{key='';$('key').value='';$('connection').textContent='Disconnected';$('connection').className='status muted';$('featuresOut').textContent='Admin connection required';$('historyOut').textContent='Admin connection required'};
$('health').onclick=async()=>{try{const d=await req('/health',{headers:{}});$('healthOut').textContent=JSON.stringify(d,null,2);$('serverState').textContent='Online';$('serverState').className='status good'}catch(e){$('healthOut').textContent=e.message;$('serverState').textContent='Unavailable';$('serverState').className='status bad'}};
$('history').onclick=async()=>{try{$('historyOut').textContent=JSON.stringify(await req('/v1/commands'),null,2)}catch(e){$('historyOut').textContent=e.message}};
</script></body></html>'''
