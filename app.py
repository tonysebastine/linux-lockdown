from __future__ import annotations
import hmac
import os
import subprocess
from pathlib import Path
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

APP_DIR = Path(__file__).resolve().parent
AUDIT_SCRIPT = APP_DIR / "linux-lockdown-audit.sh"
app = FastAPI(title="Linux Lockdown", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)
security = HTTPBasic()
USERNAME = os.environ.get("LOCKDOWN_USERNAME", "")
PASSWORD = os.environ.get("LOCKDOWN_PASSWORD", "")


def require_auth(credentials: Annotated[HTTPBasicCredentials, Depends(security)]) -> str:
    if not USERNAME or not PASSWORD:
        raise HTTPException(status_code=503, detail="Dashboard credentials are not configured")
    user_ok = hmac.compare_digest(credentials.username.encode(), USERNAME.encode())
    pass_ok = hmac.compare_digest(credentials.password.encode(), PASSWORD.encode())
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials", headers={"WWW-Authenticate": "Basic"})
    return credentials.username


class RunRequest(BaseModel):
    mode: str = Field(default="audit", pattern="^(audit|dry-run|execute)$")
    scope: str = Field(default="all", pattern="^(all|ssh|firewall|web|system)$")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/", response_class=HTMLResponse)
def dashboard(_: Annotated[str, Depends(require_auth)]):
    return HTML


@app.post("/api/run")
def run_audit(request: RunRequest, _: Annotated[str, Depends(require_auth)]):
    if request.mode == "execute":
        raise HTTPException(status_code=409, detail="Execute mode is disabled in this release. No changes were made. Review the dry-run plan; execution will be enabled only after control-specific remediation, backups, rollback, SSH recovery checks, and verification are implemented.")
    if request.mode == "dry-run":
        return {
            "mode": "dry-run", "scope": request.scope,
            "message": "Preview only. No commands were executed and no files or services were changed.",
            "plan": [
                "Detect OS and installed software using read-only checks",
                "Review SSH configuration and remote-access recovery requirements",
                "Review firewall policy without modifying it",
                "Identify control-panel and application-specific compatibility constraints",
                "Produce a change-by-change plan for manual review; no changes will be applied"
            ]
        }
    if not AUDIT_SCRIPT.is_file():
        raise HTTPException(status_code=500, detail="Audit script is missing")
    try:
        result = subprocess.run(["bash", str(AUDIT_SCRIPT)], cwd=str(APP_DIR), capture_output=True, text=True, timeout=20, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Audit timed out")
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail="Audit failed; check server logs")
    return {"mode": "audit", "scope": request.scope, "report": result.stdout, "message": "Read-only audit completed. No changes were made."}


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>Linux Lockdown</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;color:#e8edf5;background:#0b1020}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 10% 0%,#17264b 0,transparent 42%),#0b1020;min-height:100vh}.wrap{max-width:1050px;margin:auto;padding:28px 18px 56px}.top{display:flex;align-items:center;gap:14px;margin:12px 0 28px}.logo{display:grid;place-items:center;width:48px;height:48px;border:1px solid #31466e;background:#13213e;border-radius:14px;font-size:24px}.muted{color:#9baac3}.tag{border:1px solid #35547c;color:#a9d3ff;padding:5px 9px;border-radius:999px;font-size:12px}.hero h1{font-size:clamp(28px,5vw,42px);margin:0 0 8px;letter-spacing:-1px}.hero p{max-width:680px;line-height:1.6;color:#aebbd0;margin:0 0 24px}.panel{background:#111a2d;border:1px solid #263650;border-radius:18px;padding:22px;margin:16px 0;box-shadow:0 18px 50px #0002}.label{display:block;font-weight:650;margin-bottom:10px}.modes{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.mode{border:1px solid #2d3d58;border-radius:13px;padding:15px;background:#0e1729;cursor:pointer;display:block;min-height:128px}.mode:has(input:checked){border-color:#69a9ff;background:#142746;box-shadow:inset 0 0 0 1px #69a9ff}.mode input{accent-color:#70b1ff}.mode strong{display:block;margin:10px 0 6px}.mode small{display:block;color:#a6b5cb;line-height:1.45}.controls{display:grid;grid-template-columns:1fr auto;gap:16px;align-items:end;margin-top:20px}.select{display:block;width:100%;padding:12px;border-radius:10px;border:1px solid #344661;background:#0b1425;color:#e8edf5;font:inherit}.btn{background:#77b5ff;color:#071327;border:0;padding:13px 19px;border-radius:10px;font-weight:750;font-size:14px;cursor:pointer}.btn:disabled{opacity:.55;cursor:wait}.notice{margin-top:18px;padding:13px 15px;border-radius:10px;background:#1b2c46;color:#bcdcff;font-size:14px;line-height:1.5}.notice.warn{background:#3a2919;color:#ffd9a6}.result{white-space:pre-wrap;overflow-wrap:anywhere;background:#080d18;border:1px solid #263650;border-radius:12px;padding:16px;min-height:70px;font:13px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;max-height:520px;overflow:auto}.footer{font-size:12px;color:#8796af;text-align:center;margin-top:28px}@media(max-width:650px){.wrap{padding:18px 12px 36px}.panel{padding:16px}.modes{grid-template-columns:1fr}.mode{min-height:0}.controls{grid-template-columns:1fr}.btn{width:100%}}
</style></head><body><main class="wrap"><header class="top"><div class="logo">⛨</div><div><strong>LINUX LOCKDOWN</strong><div class="muted" style="font-size:12px;margin-top:4px">Server security · Safe by default</div></div><span class="tag" style="margin-left:auto">MVP 0.1</span></header>
<section class="hero"><h1>Harden with confidence.</h1><p>Inspect a Linux server, preview hardening recommendations, and keep control over every change. The current release is deliberately read-only; execution is disabled until safeguards are implemented and validated.</p></section>
<section class="panel"><span class="label">01 / Choose execution mode</span><div class="modes">
<label class="mode"><input type="radio" name="mode" value="audit" checked><strong>Audit only</strong><small>Inspect the local host and return a read-only report.</small></label>
<label class="mode"><input type="radio" name="mode" value="dry-run"><strong>Dry run</strong><small>Preview the proposed review steps without changing the server.</small></label>
<label class="mode"><input type="radio" name="mode" value="execute"><strong>Execute changes</strong><small>Not yet available. This release will not apply system changes.</small></label>
</div><div class="controls"><div><label class="label" for="scope">02 / Audit scope</label><select id="scope" class="select"><option value="all">All detected categories</option><option value="ssh">SSH and remote access</option><option value="firewall">Firewall and network exposure</option><option value="web">Web server and application stack</option><option value="system">OS, accounts and system settings</option></select></div><button class="btn" id="run">Run selected mode →</button></div><div class="notice" id="notice">Safe mode enabled: audit and dry-run never modify the host.</div></section>
<section class="panel"><span class="label">03 / Result</span><div id="result" class="result" role="status" aria-live="polite">Select a mode and run it to view the report.</div></section><p class="footer">Run behind HTTPS · Use a unique password · Do not expose the app server directly</p></main>
<script>
const btn=document.getElementById('run'),out=document.getElementById('result'),notice=document.getElementById('notice');
function mode(){return document.querySelector('input[name="mode"]:checked').value}
document.querySelectorAll('input[name="mode"]').forEach(el=>el.addEventListener('change',()=>{if(mode()==='execute'){notice.className='notice warn';notice.textContent='Execution is disabled in this release. Submitting will be rejected safely; no changes can be applied.'}else{notice.className='notice';notice.textContent='Safe mode enabled: audit and dry-run never modify the host.'}}));
btn.addEventListener('click',async()=>{btn.disabled=true;out.textContent='Working…';try{const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:mode(),scope:document.getElementById('scope').value})});const d=await r.json();if(!r.ok){out.textContent='Request not applied\n\n'+(d.detail||'Request failed');return}if(d.report){out.textContent=d.message+'\n\n'+d.report}else{out.textContent=d.message+'\n\n'+d.plan.map((x,i)=>(i+1)+'. '+x).join('\n')}}catch(e){out.textContent='Could not reach the API. Check the service and reverse proxy.'}finally{btn.disabled=false}});
</script></body></html>'''
