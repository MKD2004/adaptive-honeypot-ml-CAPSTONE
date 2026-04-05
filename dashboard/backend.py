"""
dashboard/backend.py — Flask + SSE backend (no extra deps beyond Flask)
"""
from __future__ import annotations
import argparse, json, os, queue, random, socket, sys, threading, time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from flask import Flask, Response, jsonify, send_file

_ROOT        = Path(__file__).parent
_STATIC      = _ROOT / "static"
_DEFAULT_LOG = _ROOT.parent / "traffic_gateway" / "data" / "sessions.jsonl"

@dataclass
class IPState:
    ip: str; status: str = "unknown"; request_count: int = 0
    blocked_count: int = 0; bytes_in: int = 0; bytes_out: int = 0
    last_event: str = ""; last_seen: str = ""; risk_score: float = 0.5
    honeypot_hits: int = 0
    def to_dict(self): return asdict(self)

def _utcnow(): return datetime.now(timezone.utc).isoformat()

class DashboardState:
    def __init__(self):
        self._lock = threading.Lock()
        self.ips: Dict[str, IPState] = {}
        self.metrics = dict(total_connections=0,active_connections=0,blocked_ips=0,
            honeypot_redirects=0,whitelist_count=0,suspicious_count=0,rate_limit_events=0)
        self.recent_events: deque = deque(maxlen=200)
        self._timeline: Dict[str,int] = {}
        self._seq = 0

    def process_event(self, raw: dict) -> dict:
        ip = raw.get("ip","system"); t = raw.get("event",""); ts = raw.get("ts",_utcnow())
        with self._lock:
            if ip != "system" and ip not in self.ips: self.ips[ip] = IPState(ip=ip)
            if ip in self.ips:
                r = self.ips[ip]; r.last_seen=ts; r.last_event=t; r.request_count+=1
            m = self.metrics
            if t=="CONN_RECEIVED":   m["total_connections"]+=1; m["active_connections"]+=1
            elif t=="CONN_CLOSED":
                m["active_connections"]=max(0,m["active_connections"]-1)
                if ip in self.ips: self.ips[ip].bytes_in+=raw.get("bytes_in",0); self.ips[ip].bytes_out+=raw.get("bytes_out",0)
            elif t=="CONN_ROUTED":
                if raw.get("target_type")=="honeypot":
                    m["honeypot_redirects"]+=1
                    if ip in self.ips: self.ips[ip].honeypot_hits+=1
            elif t in ("IP_BLACKLISTED","PROBATION_REVOKED"):
                if ip in self.ips: self.ips[ip].status="blacklisted"; self.ips[ip].blocked_count+=1
                self._rc()
            elif t=="IP_SUSPICIOUS":
                if ip in self.ips: self.ips[ip].status="suspicious"; self._rc()
            elif t=="IP_CLASSIFIED":
                ns=raw.get("new_status","")
                if ip in self.ips and ns: self.ips[ip].status=ns; self._rc()
            elif t=="PROMOTION_APPROVED":
                if ip in self.ips: self.ips[ip].status="whitelisted"; self._rc()
            elif t in ("PROMOTION_PROBATION","PROBATION_STRIKE"):
                if ip in self.ips and t=="PROMOTION_PROBATION": self.ips[ip].status="probation"; self._rc()
            elif t=="ML_ASSESSMENT":
                if ip in self.ips: self.ips[ip].risk_score=round(raw.get("score",0.5),3)
            elif t=="RATE_LIMITED":
                m["rate_limit_events"]+=1
                if ip in self.ips: self.ips[ip].blocked_count+=1
            b=ts[:19]; self._timeline[b]=self._timeline.get(b,0)+1
            if len(self._timeline)>120:
                for k in sorted(self._timeline)[:60]: del self._timeline[k]
            self._seq+=1; e={**raw,"_seq":self._seq}; self.recent_events.appendleft(e)
            return {"event":e,"ip_state":self.ips[ip].to_dict() if ip in self.ips else None,"metrics":dict(self.metrics)}

    def full_state(self) -> dict:
        with self._lock:
            tl=[{"ts":b,"count":self._timeline[b]} for b in sorted(self._timeline)[-60:]]
            return {"ips":{ip:r.to_dict() for ip,r in self.ips.items()},
                    "metrics":dict(self.metrics),"recent_events":list(self.recent_events),"timeline":tl}

    def _rc(self):
        self.metrics["blocked_ips"]     =sum(1 for r in self.ips.values() if r.status=="blacklisted")
        self.metrics["whitelist_count"] =sum(1 for r in self.ips.values() if r.status=="whitelisted")
        self.metrics["suspicious_count"]=sum(1 for r in self.ips.values() if r.status=="suspicious")

_qs: List[queue.Queue] = []; _ql = threading.Lock()

def _bc(data: dict):
    p=f"data: {json.dumps(data,default=str)}\n\n"
    with _ql:
        dead=[]
        for q in _qs:
            try: q.put_nowait(p)
            except queue.Full: dead.append(q)
        for q in dead: _qs.remove(q)

def _tail(path: Path, state: DashboardState):
    while not path.exists(): time.sleep(1)
    with open(path) as f:
        f.seek(0,2)
        while True:
            l=f.readline()
            if l and l.strip():
                try: _bc({"type":"update",**state.process_event(json.loads(l.strip()))})
                except: pass
            else: time.sleep(0.05)

def _demo(state: DashboardState):
    time.sleep(2.0)
    def em(evt,d=0.6):
        evt["ts"]=_utcnow(); _bc({"type":"update",**state.process_event(evt)}); time.sleep(d+random.uniform(-0.05,0.25))
    # P1 both arrive
    for ip in ["192.168.1.100","192.168.1.101"]:
        em({"event":"CONN_RECEIVED","ip":ip,"active_connections":1,"ip_status":"unknown"},0.3)
        em({"event":"CONN_ROUTED","ip":ip,"target_type":"honeypot","reason":"unknown_zero_trust_redirect"},0.25)
        em({"event":"CONN_CLOSED","ip":ip,"bytes_in":random.randint(200,800),"bytes_out":random.randint(50,300),"duration_sec":round(random.uniform(0.8,3),2),"entropy":3.4},0.45)
    # P2 .101 normal
    for _ in range(3):
        em({"event":"CONN_RECEIVED","ip":"192.168.1.101","active_connections":1,"ip_status":"unknown"},0.35)
        em({"event":"CONN_ROUTED","ip":"192.168.1.101","target_type":"honeypot","reason":"unknown_zero_trust_redirect"},0.25)
        em({"event":"CONN_CLOSED","ip":"192.168.1.101","bytes_in":random.randint(400,900),"bytes_out":random.randint(200,600),"duration_sec":round(random.uniform(1.5,5),2),"entropy":3.1},0.6)
    # P3 .100 scanner
    for _ in range(5):
        em({"event":"CONN_RECEIVED","ip":"192.168.1.100","active_connections":2,"ip_status":"unknown"},0.18)
        em({"event":"CONN_ROUTED","ip":"192.168.1.100","target_type":"honeypot","reason":"unknown_zero_trust_redirect"},0.12)
        em({"event":"CONN_CLOSED","ip":"192.168.1.100","bytes_in":random.randint(10,50),"bytes_out":0,"duration_sec":0.07,"entropy":round(random.uniform(6.2,7.5),3)},0.2)
    em({"event":"ML_ASSESSMENT","ip":"192.168.1.100","score":0.62,"reasoning":"high entropy + sub-second sessions"},0.45)
    em({"event":"IP_SUSPICIOUS","ip":"192.168.1.100","old_status":"unknown","new_status":"suspicious","risk_score":0.62},0.55)
    # P4 rate limit
    time.sleep(0.3)
    for _ in range(4): em({"event":"CONN_RECEIVED","ip":"10.0.0.47","active_connections":3,"ip_status":"unknown"},0.12)
    em({"event":"RATE_LIMITED","ip":"10.0.0.47","reason":"window_exceeded","connections_in_window":20,"window_sec":60,"block_sec":300},0.5)
    # P5 .100 escalate
    for _ in range(4):
        em({"event":"CONN_RECEIVED","ip":"192.168.1.100","active_connections":2,"ip_status":"suspicious"},0.12)
        em({"event":"CONN_ROUTED","ip":"192.168.1.100","target_type":"honeypot","reason":"suspicious_redirect"},0.08)
        em({"event":"CONN_CLOSED","ip":"192.168.1.100","bytes_in":random.randint(8,30),"bytes_out":0,"duration_sec":0.05,"entropy":7.1},0.18)
    em({"event":"ML_ASSESSMENT","ip":"192.168.1.100","score":0.84,"reasoning":"brute-force + obfuscated payload"},0.35)
    em({"event":"IP_BLACKLISTED","ip":"192.168.1.100","reason":"Auto-blacklisted: score=0.84","source":"reputation_scorer","risk_score":0.84},0.7)
    # P6 .12
    time.sleep(0.4); em({"event":"CONN_RECEIVED","ip":"172.16.0.12","active_connections":1,"ip_status":"unknown"},0.4)
    em({"event":"ML_ASSESSMENT","ip":"172.16.0.12","score":0.52},0.3)
    em({"event":"IP_SUSPICIOUS","ip":"172.16.0.12","old_status":"unknown","new_status":"suspicious"},0.5)
    # P7 .101 probation
    time.sleep(1.1); em({"event":"ML_ASSESSMENT","ip":"192.168.1.101","score":0.18,"reasoning":"benign browsing pattern"},0.5)
    em({"event":"PROMOTION_ELIGIBLE","ip":"192.168.1.101","message":"entered review queue"},0.6)
    em({"event":"PROMOTION_PROBATION","ip":"192.168.1.101","ml_score":0.18,"reasoning":"score below threshold"},0.4)
    em({"event":"IP_CLASSIFIED","ip":"192.168.1.101","old_status":"unknown","new_status":"probation"},0.7)
    # P8 .100 review
    time.sleep(1.6); em({"event":"PROMOTION_ELIGIBLE","ip":"192.168.1.100","message":"min blacklist time served"},0.5)
    em({"event":"ML_ASSESSMENT","ip":"192.168.1.100","score":0.21,"reasoning":"activity normalized"},0.4)
    em({"event":"PROMOTION_PROBATION","ip":"192.168.1.100","ml_score":0.21,"reasoning":"score below threshold"},0.4)
    em({"event":"IP_CLASSIFIED","ip":"192.168.1.100","old_status":"blacklisted","new_status":"probation"},0.7)
    # P9 .101 whitelist
    time.sleep(2.2); em({"event":"ML_ASSESSMENT","ip":"192.168.1.101","score":0.11,"reasoning":"probation clean"},0.4)
    em({"event":"PROMOTION_APPROVED","ip":"192.168.1.101","ml_score":0.11,"reasoning":"probation complete"},0.35)
    em({"event":"IP_CLASSIFIED","ip":"192.168.1.101","old_status":"probation","new_status":"whitelisted"},0.3)
    em({"event":"CONN_ROUTED","ip":"192.168.1.101","target_type":"backend","reason":"whitelisted"},0.7)
    # P10 .100 whitelist
    time.sleep(2.0); em({"event":"ML_ASSESSMENT","ip":"192.168.1.100","score":0.16,"reasoning":"probation complete"},0.4)
    em({"event":"PROMOTION_APPROVED","ip":"192.168.1.100","ml_score":0.16,"reasoning":"probation complete"},0.3)
    em({"event":"IP_CLASSIFIED","ip":"192.168.1.100","old_status":"probation","new_status":"whitelisted"},0.5)
    # Trickle
    while True:
        ip=random.choice(["192.168.1.100","192.168.1.101"])
        em({"event":"CONN_RECEIVED","ip":ip,"active_connections":random.randint(0,2),"ip_status":"whitelisted"},0.4)
        em({"event":"CONN_ROUTED","ip":ip,"target_type":"backend","reason":"whitelisted"},0.25)
        em({"event":"CONN_CLOSED","ip":ip,"bytes_in":random.randint(200,3000),"bytes_out":random.randint(100,1500),"duration_sec":round(random.uniform(0.5,8),2),"entropy":round(random.uniform(2.5,4.5),3)},random.uniform(2,5))

app=Flask(__name__); _state: Optional[DashboardState]=None; _demo_mode=False

@app.route("/")
def idx(): return send_file(_STATIC/"index.html")

@app.route("/api/state")
def api_state(): return jsonify(_state.full_state())

@app.route("/api/demo")
def api_demo(): return jsonify({"demo_mode":_demo_mode})

@app.route("/events")
def sse():
    q2: queue.Queue=queue.Queue(maxsize=300)
    with _ql: _qs.append(q2)
    init=json.dumps({"type":"init","demo_mode":_demo_mode,**_state.full_state()},default=str)
    def gen():
        try:
            yield f"data: {init}\n\n"
            while True:
                try: yield q2.get(timeout=20)
                except queue.Empty: yield ": hb\n\n"
        finally:
            with _ql:
                try: _qs.remove(q2)
                except ValueError: pass
    return Response(gen(),mimetype="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no","Access-Control-Allow-Origin":"*"})

def _lip():
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s: s.connect(("8.8.8.8",80)); return s.getsockname()[0]
    except: return "127.0.0.1"

def main():
    global _state,_demo_mode
    p=argparse.ArgumentParser(); p.add_argument("--log-file",default=str(_DEFAULT_LOG))
    p.add_argument("--host",default="0.0.0.0"); p.add_argument("--port",type=int,default=5000)
    p.add_argument("--demo",action="store_true"); a=p.parse_args()
    lp=Path(a.log_file); _demo_mode=a.demo or not lp.exists(); _state=DashboardState()
    fn=_demo if _demo_mode else lambda s:_tail(lp,s)
    threading.Thread(target=fn,args=(_state,),daemon=True).start()
    lip=_lip(); print(f"\n  DEMO MODE" if _demo_mode else f"\n  Tailing: {lp}")
    print(f"  Dashboard : http://localhost:{a.port}")
    print(f"  LAN URL   : http://{lip}:{a.port}  <-- share this!\n")
    import logging; logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host=a.host,port=a.port,threaded=True)

if __name__=="__main__": main()
