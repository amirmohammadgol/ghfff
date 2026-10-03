import base64, hmac, json, os, secrets, sqlite3, subprocess, time, uuid, urllib.parse, threading, re, io, html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB=os.environ.get('VPNSTAN_WEB','/opt/vpnstan/web')
DB=os.environ.get('VPNSTAN_DB','/data/vpnstan.db')
PANEL_PORT=int(os.environ.get('VPNSTAN_PANEL_PORT','3000'))
USERNAME=os.environ.get('VPNSTAN_USERNAME','admin')
PASSWORD=os.environ.get('VPNSTAN_PASSWORD','admin')
DEFAULT_HOST=os.environ.get('VPNSTAN_NODE_HOST','')
DEFAULT_PORT=int(os.environ.get('VPNSTAN_NODE_PORT','443'))
DEFAULT_PATH=os.environ.get('VPNSTAN_WS_PATH','/ws')
SUB_PATH=os.environ.get('VPNSTAN_SUB_PATH','sub')
XRAY_BIN=os.environ.get('XRAY_BIN','/usr/local/bin/xray')
XRAY_CONFIG=os.environ.get('XRAY_CONFIG','/data/xray.json')
XRAY_INBOUND_PORT=int(os.environ.get('XRAY_INBOUND_PORT','10000'))
XRAY_VMESS_PORT=int(os.environ.get('XRAY_VMESS_PORT','10001'))
DEFAULT_VMESS_PATH=os.environ.get('VPNSTAN_VMESS_PATH','/vmess')
XRAY_API_ADDR=os.environ.get('XRAY_API_ADDR','127.0.0.1:10085')
SESSIONS={}
XRAY_PROC=None
SESSION_USERS={}

XRAY_LOCK=threading.RLock()


def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    os.makedirs(os.path.dirname(DB),exist_ok=True)
    c=db()
    c.execute('''CREATE TABLE IF NOT EXISTS clients(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, uuid TEXT NOT NULL UNIQUE,
      sub_id TEXT NOT NULL UNIQUE, gb REAL NOT NULL, days INTEGER NOT NULL,
      created_at INTEGER NOT NULL, expiry_at INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)''')
    c.execute('''CREATE TABLE IF NOT EXISTS panel_users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
      enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS traffic(
      client_id INTEGER PRIMARY KEY, upload INTEGER NOT NULL DEFAULT 0,
      download INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0,
      raw_upload INTEGER NOT NULL DEFAULT 0, raw_download INTEGER NOT NULL DEFAULT 0)''')
    for col in ('raw_upload','raw_download'):
        try: c.execute(f'ALTER TABLE traffic ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0')
        except sqlite3.OperationalError: pass
    for col,typ,default in [('protocol','TEXT',"'vless'"),('dns_server','TEXT',"'1.1.1.1'"),('wg_private_key','TEXT',"''"),('wg_address','TEXT',"''")]:
        try: c.execute(f'ALTER TABLE clients ADD COLUMN {col} {typ} NOT NULL DEFAULT {default}')
        except sqlite3.OperationalError: pass
    # Seed the first administrator from environment variables, only on first startup.
    if c.execute('SELECT COUNT(*) FROM panel_users').fetchone()[0] == 0:
        import hashlib
        ph=hashlib.sha256(PASSWORD.encode()).hexdigest()
        c.execute('INSERT INTO panel_users(username,password_hash,role,enabled,created_at) VALUES(?,?,?,?,?)',(USERNAME,ph,'admin',1,int(time.time())))
    defaults={'node_host':DEFAULT_HOST,'node_port':str(DEFAULT_PORT),'ws_path':DEFAULT_PATH,'vmess_path':DEFAULT_VMESS_PATH,'sub_path':SUB_PATH,
              'panel_title':'vpnstan','support_url':'','dns_server':'1.1.1.1','wg_endpoint':'','wg_server_public_key':'','announce':'اشتراک vpnstan — برای دریافت آخرین کانفیگ، لینک اشتراک را به‌روزرسانی کنید.','update_interval':'6'}
    for k,v in defaults.items(): c.execute('INSERT OR IGNORE INTO settings(k,v) VALUES(?,?)',(k,v))
    c.commit(); c.close()

def hash_password(v):
    import hashlib
    return hashlib.sha256(str(v).encode()).hexdigest()

def current_user(h):
    for x in h.headers.get('Cookie','').split(';'):
        if x.strip().startswith('vpnstan_session='):
            t=x.strip().split('=',1)[1]
            if SESSIONS.get(t,0)>time.time():
                uid=SESSION_USERS.get(t)
                if uid:
                    c=db(); r=c.execute('SELECT id,username,role,enabled FROM panel_users WHERE id=?',(uid,)).fetchone(); c.close()
                    if r and r['enabled']: return r
    return None

def is_admin(h):
    u=current_user(h); return bool(u and u['role']=='admin')

def auth_error(h):
    return send(h,401,{'success':False,'msg':'نیاز به ورود دارید'})

def settings():
    c=db(); rows=c.execute('SELECT k,v FROM settings').fetchall(); c.close(); return {r['k']:r['v'] for r in rows}

def set_setting(k,v):
    c=db(); c.execute('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',(k,str(v))); c.commit(); c.close()

def active_clients():
    c=db(); rows=c.execute('SELECT * FROM clients WHERE enabled=1 ORDER BY id').fetchall(); c.close(); now=int(time.time()); return [r for r in rows if r['expiry_at']==0 or r['expiry_at']>now]

def traffic_for(cid):
    c=db(); r=c.execute('SELECT upload,download,last_seen FROM traffic WHERE client_id=?',(cid,)).fetchone(); c.close()
    return {'upload':int(r['upload']) if r else 0,'download':int(r['download']) if r else 0,'last_seen':int(r['last_seen']) if r else 0}

def fmt_bytes(n):
    n=max(0,int(n)); units=['B','KB','MB','GB','TB']
    x=float(n); i=0
    while x>=1024 and i<len(units)-1: x/=1024; i+=1
    return f'{x:.2f} {units[i]}' if i else f'{int(x)} B'

def fmt_date(ts):
    if not ts:return 'نامحدود'
    return time.strftime('%Y/%m/%d %H:%M',time.localtime(ts))

def collect_xray_stats():
    if not os.path.exists(XRAY_BIN): return
    try:
        raw=subprocess.check_output([XRAY_BIN,'api','statsquery','-s',XRAY_API_ADDR],stderr=subprocess.DEVNULL,timeout=5)
        data=json.loads(raw.decode('utf-8','replace'))
    except Exception:
        return
    stats={}
    for item in data.get('stat',[]):
        name=item.get('name',''); value=int(item.get('value',0) or 0)
        m=re.match(r'^user>>>(.+)>>>traffic>>>(uplink|downlink)$',name)
        if m:
            email,kind=m.group(1),m.group(2); stats.setdefault(email,{'upload':0,'download':0})[kind]=value
    if not stats:return
    c=db(); now=int(time.time())
    rows=c.execute('SELECT id,name FROM clients').fetchall()
    for r in rows:
        st=stats.get(r['name'])
        if not st: continue
        old=c.execute('SELECT upload,download,last_seen,raw_upload,raw_download FROM traffic WHERE client_id=?',(r['id'],)).fetchone()
        if not old:
            total_u=0; total_d=0; delta_u=0; delta_d=0; last=0
        else:
            raw_u=int(old['raw_upload']); raw_d=int(old['raw_download'])
            # Xray counters reset on each Xray restart. When that happens, use the new
            # counter as the new baseline rather than subtracting it from cumulative usage.
            delta_u=(st['upload']-raw_u) if st['upload']>=raw_u else st['upload']
            delta_d=(st['download']-raw_d) if st['download']>=raw_d else st['download']
            total_u=int(old['upload'])+max(0,delta_u)
            total_d=int(old['download'])+max(0,delta_d)
            last=now if delta_u+delta_d>0 else int(old['last_seen'])
        c.execute('''INSERT INTO traffic(client_id,upload,download,last_seen,raw_upload,raw_download) VALUES(?,?,?,?,?,?)
                     ON CONFLICT(client_id) DO UPDATE SET upload=excluded.upload,download=excluded.download,last_seen=excluded.last_seen,raw_upload=excluded.raw_upload,raw_download=excluded.raw_download''',
                  (r['id'],total_u,total_d,last,st['upload'],st['download']))
    c.commit()
    rows=c.execute('SELECT id,gb,expiry_at,enabled FROM clients').fetchall()
    for r in rows:
        if not r['enabled'] or (r['expiry_at'] and r['expiry_at']<=now): continue
        tr=c.execute('SELECT upload,download FROM traffic WHERE client_id=?',(r['id'],)).fetchone()
        if tr and int(tr['upload'])+int(tr['download']) >= float(r['gb'])*1024**3:
            c.execute('UPDATE clients SET enabled=0 WHERE id=?',(r['id'],))
    c.commit(); c.close()

def write_xray_config():
    os.makedirs(os.path.dirname(XRAY_CONFIG),exist_ok=True)
    s=settings(); vpath=s.get('ws_path','/ws') or '/ws'; mpath=s.get('vmess_path','/vmess') or '/vmess'
    rows=active_clients()
    vclients=[{'id':r['uuid'],'email':r['name'],'level':0} for r in rows if (r['protocol'] or 'vless')=='vless']
    mclients=[{'id':r['uuid'],'email':r['name'],'level':0,'alterId':0} for r in rows if (r['protocol'] or 'vless')=='vmess']
    inbounds=[]
    if vclients:
        inbounds.append({'tag':'vless-ws','listen':'127.0.0.1','port':XRAY_INBOUND_PORT,'protocol':'vless',
            'settings':{'clients':vclients,'decryption':'none'},
            'streamSettings':{'network':'ws','security':'none','wsSettings':{'path':vpath}}})
    if mclients:
        inbounds.append({'tag':'vmess-ws','listen':'127.0.0.1','port':XRAY_VMESS_PORT,'protocol':'vmess',
            'settings':{'clients':mclients},
            'streamSettings':{'network':'ws','security':'none','wsSettings':{'path':mpath}}})
    cfg={'log':{'loglevel':'warning'},'api':{'tag':'api','listen':XRAY_API_ADDR,'services':['StatsService']},'stats':{},
      'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True,'statsUserOnline':True}},'system':{'statsInboundUplink':True,'statsInboundDownlink':True}},
      'inbounds':inbounds,'outbounds':[{'protocol':'freedom','tag':'direct'},{'protocol':'blackhole','tag':'block'}]}
    tmp=XRAY_CONFIG+'.tmp'
    with open(tmp,'w',encoding='utf-8') as f: json.dump(cfg,f,ensure_ascii=False,indent=2)
    os.replace(tmp,XRAY_CONFIG); return cfg

def restart_xray():
    global XRAY_PROC
    with XRAY_LOCK:
        collect_xray_stats()
        write_xray_config()
        if XRAY_PROC and XRAY_PROC.poll() is None:
            XRAY_PROC.terminate()
            try: XRAY_PROC.wait(timeout=3)
            except subprocess.TimeoutExpired: XRAY_PROC.kill()
        try:
            test=subprocess.run([XRAY_BIN,'run','-test','-c',XRAY_CONFIG],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=8)
            if test.returncode != 0:
                print('XRAY CONFIG TEST FAILED:',test.stdout.decode('utf-8','replace')[-4000:],flush=True)
                return
            log=open('/data/xray.log','ab')
            XRAY_PROC=subprocess.Popen([XRAY_BIN,'run','-c',XRAY_CONFIG],stdout=log,stderr=log)
            time.sleep(0.5)
            if XRAY_PROC.poll() is not None: print('XRAY FAILED — see /data/xray.log',flush=True)
            else: print('Xray started with',len(active_clients()),'active client(s)',flush=True)
        except Exception as e: print('XRAY START ERROR:',e,flush=True)

def collector_loop():
    while True:
        try:
            with XRAY_LOCK:
                before=[(r['id'],int(r['enabled'])) for r in db().execute('SELECT id,enabled FROM clients').fetchall()]
                collect_xray_stats()
                after=[(r['id'],int(r['enabled'])) for r in db().execute('SELECT id,enabled FROM clients').fetchall()]
                if before != after:
                    write_xray_config()
                    if XRAY_PROC and XRAY_PROC.poll() is None:
                        XRAY_PROC.terminate()
                        try: XRAY_PROC.wait(timeout=3)
                        except subprocess.TimeoutExpired: XRAY_PROC.kill()
                        log=open('/data/xray.log','ab')
                        globals()['XRAY_PROC']=subprocess.Popen([XRAY_BIN,'run','-c',XRAY_CONFIG],stdout=log,stderr=log)
        except Exception as e: print('STATS ERROR:',e,flush=True)
        time.sleep(15)

def authed(h):
    return current_user(h) is not None

def body(h):
    n=int(h.headers.get('Content-Length','0')); return json.loads(h.rfile.read(n) or b'{}')

def send(h,status,obj,extra=None):
    raw=json.dumps(obj,ensure_ascii=False).encode(); h.send_response(status); h.send_header('Content-Type','application/json; charset=utf-8'); h.send_header('Content-Length',str(len(raw))); h.send_header('Cache-Control','no-store')
    for k,v in (extra or {}).items(): h.send_header(k,v)
    h.end_headers(); h.wfile.write(raw)

def clean_host(v): return (v or '').split(':',1)[0].strip()
def host_for(h,s):
    return (clean_host(s.get('node_host')) or clean_host(os.environ.get('RAILWAY_PUBLIC_DOMAIN')) or clean_host(h.headers.get('X-Forwarded-Host') or h.headers.get('Host','')))


def link_for(h,r,s):
    proto=(r['protocol'] if 'protocol' in r.keys() else 'vless') or 'vless'
    host=host_for(h,s); name=urllib.parse.quote(r['name'])
    if proto=='wireguard': return wg_config_for(h,r,s)
    if proto=='dns': return f'dns://{r["dns_server"] or s.get("dns_server","1.1.1.1")}:53#{name}'
    port=int(s.get('node_port','443'));
    if proto=='vmess':
        obj={'v':'2','ps':r['name'],'add':host,'port':str(port),'id':r['uuid'],'aid':'0','scy':'auto','net':'ws','type':'none','host':host,'path':s.get('vmess_path','/vmess') or '/vmess','tls':'tls','sni':host}
        return 'vmess://'+base64.b64encode(json.dumps(obj,separators=(',',':'),ensure_ascii=False).encode()).decode()
    path=s.get('ws_path','/ws') or '/ws'
    qp=urllib.parse.urlencode({'encryption':'none','security':'tls','type':'ws','host':host,'path':path,'sni':host},safe='/')
    return f'vless://{r["uuid"]}@{host}:{port}?{qp}#{name}'

def wg_config_for(h,r,s):
    endpoint=s.get('wg_endpoint','') or 'SET-WIREGUARD-ENDPOINT:51820'
    server_key=s.get('wg_server_public_key','') or 'SET-SERVER-PUBLIC-KEY'
    private=r['wg_private_key'] or 'GENERATE-CLIENT-PRIVATE-KEY'
    addr=r['wg_address'] or '10.66.0.2/32'
    dns=r['dns_server'] or s.get('dns_server','1.1.1.1')
    return f'[Interface]\nPrivateKey = {private}\nAddress = {addr}\nDNS = {dns}\n\n[Peer]\nPublicKey = {server_key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {endpoint}\nPersistentKeepalive = 25'

def client_data(h,r,s):
    now=int(time.time()); tr=traffic_for(r['id']); used=tr['upload']+tr['download']; total=int(float(r['gb'])*1024**3); remain=max(0,total-used)
    sub_host=host_for(h,s); sub=f'https://{sub_host}/{s.get("sub_path","sub").strip("/")}/{r["sub_id"]}'
    online=(tr['last_seen'] and now-tr['last_seen']<=90)
    return {'id':r['id'],'name':r['name'],'protocol':r['protocol'] or 'vless','uuid':r['uuid'],'subId':r['sub_id'],'gb':r['gb'],'days':r['days'],'createdAt':r['created_at'],'expiryAt':r['expiry_at'],'enabled':bool(r['enabled']),
            'upload':tr['upload'],'download':tr['download'],'used':used,'remaining':remain,'totalBytes':total,'lastSeen':tr['last_seen'],'online':bool(online),
            'remainingText':fmt_bytes(remain),'usedText':fmt_bytes(used),'totalText':fmt_bytes(total),'uploadText':fmt_bytes(tr['upload']),'downloadText':fmt_bytes(tr['download']),
            'expiryText':fmt_date(r['expiry_at']),'vless':link_for(h,r,s),'config':link_for(h,r,s),'subscription':sub,'dnsServer':r['dns_server'] or s.get('dns_server','1.1.1.1'),'wireguardConfig':wg_config_for(h,r,s)}

def load_sub(h,sid):
    s=settings(); c=db(); rows=c.execute('SELECT * FROM clients WHERE sub_id=? AND enabled=1',(sid,)).fetchall(); c.close(); now=int(time.time())
    rows=[r for r in rows if r['expiry_at']==0 or r['expiry_at']>now]
    return s,rows

def sub_page(h,sid):
    s,rows=load_sub(h,sid)
    if not rows:
        h.send_response(404); h.send_header('Content-Type','text/html; charset=utf-8'); h.end_headers(); h.wfile.write('<h2>اشتراک پیدا نشد یا منقضی شده است.</h2>'.encode()); return
    r=rows[0]; d=client_data(h,r,s); proto=(r['protocol'] or 'vless').upper(); title=html.escape(s.get('panel_title','vpnstan')); name=html.escape(r['name']); link=html.escape(d['vless'],quote=True); sub=html.escape(d['subscription'],quote=True)
    pct=min(100,(d['used']/d['totalBytes']*100) if d['totalBytes'] else 0); status='آنلاین' if d['online'] else 'آفلاین'
    support=html.escape(s.get('support_url',''),quote=True); announce=html.escape(s.get('announce',''))
    qr=f'/qr/{r["sub_id"]}'
    page=f'''<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#0b1020"><title>{title} — {name}</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#070b14;color:#e8eefc;font-family:Tahoma,Arial,sans-serif}}.wrap{{max-width:920px;margin:auto;padding:28px 16px 50px}}.card{{background:linear-gradient(145deg,#111827,#0b1220);border:1px solid #26324a;border-radius:22px;padding:24px;box-shadow:0 18px 50px #0006;margin-bottom:16px}}.qr-card{{text-align:center}}.qr-card .qr{{box-shadow:0 8px 30px #0005}}.top{{display:flex;justify-content:space-between;gap:15px;align-items:center}}.brand{{font-size:22px;font-weight:800}}.muted{{color:#91a0bb;font-size:13px}}h1{{font-size:25px;margin:8px 0}}h2{{font-size:17px;margin:0 0 16px}}.badge{{padding:7px 12px;border-radius:999px;background:#17233a;color:#9db8ff;font-size:12px}}.online{{color:#58e0a0}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}.stat{{background:#0a1120;border:1px solid #202d43;border-radius:16px;padding:15px}}.stat b{{display:block;font-size:18px;margin-top:6px}}.bar{{height:10px;background:#1b2639;border-radius:99px;overflow:hidden;margin:12px 0}}.fill{{height:100%;background:linear-gradient(90deg,#5b8cff,#7b5cff);border-radius:99px}}.row{{display:flex;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid #202b3d;font-size:13px}}.row:last-child{{border:0}}.code{{direction:ltr;text-align:left;background:#050811;border:1px solid #202a3c;border-radius:14px;padding:13px;word-break:break-all;font-family:Consolas,monospace;font-size:12px;color:#bcd0ff}}button,a.btn{{display:inline-block;border:0;border-radius:12px;padding:11px 15px;background:#5b72ff;color:#fff;cursor:pointer;text-decoration:none;font-weight:700;margin-top:10px}}button.secondary{{background:#18243a}}.qr{{width:170px;height:170px;background:#fff;border-radius:12px;padding:8px;display:block;margin:8px auto}}.announce{{background:#0d1729;border:1px dashed #30415f;border-radius:14px;padding:12px;color:#b9c7dd;font-size:13px}}@media(max-width:700px){{.grid{{grid-template-columns:repeat(2,1fr)}}.top{{align-items:flex-start}}}}
</style></head><body><div class="wrap"><div class="card"><div class="top"><div><div class="brand">{title}</div><div class="muted">Subscription • {proto}</div></div><div class="badge {'online' if d['online'] else ''}">● {status}</div></div><h1>{name}</h1><div class="muted">شناسه اشتراک: {html.escape(r['sub_id'])}</div></div>
<div class="card"><h2>وضعیت مصرف</h2><div class="grid"><div class="stat"><span class="muted">حجم کل</span><b>{d['totalText']}</b></div><div class="stat"><span class="muted">مصرف‌شده</span><b>{d['usedText']}</b></div><div class="stat"><span class="muted">باقی‌مانده</span><b>{d['remainingText']}</b></div><div class="stat"><span class="muted">انقضا</span><b>{html.escape(d['expiryText'])}</b></div></div><div class="bar"><div class="fill" style="width:{pct:.1f}%"></div></div><div class="row"><span>دانلود</span><b>{d['downloadText']}</b></div><div class="row"><span>آپلود</span><b>{d['uploadText']}</b></div></div>
<div class="card"><h2>کانفیگ آماده</h2><div class="muted" style="margin:-8px 0 12px">{proto} • آماده برای کپی یا اسکن</div><div class="code" id="cfg">{link}</div><button onclick="copyText('cfg')">کپی کانفیگ</button><button class="secondary" onclick="copyText('sub')">کپی لینک اشتراک</button><div id="sub" class="code" style="margin-top:10px">{sub}</div></div>
<div class="card qr-card"><h2>اتصال سریع</h2><img class="qr" src="{qr}" alt="QR"><div class="muted" style="text-align:center">QR را با کلاینت سازگار اسکن کن</div></div>
<div class="card"><h2>جزئیات اتصال</h2><div class="row"><span>پروتکل</span><b>{proto}</b></div><div class="row"><span>Transport</span><b>{('WebSocket + TLS' if proto=='VLESS' else ('WireGuard' if proto=='WIREGUARD' else 'DNS Resolver'))}</b></div><div class="row"><span>مسیر</span><b>{html.escape(s.get('ws_path','/ws'))}</b></div><div class="row"><span>آخرین فعالیت</span><b>{fmt_date(d['lastSeen']) if d['lastSeen'] else 'هنوز ثبت نشده'}</b></div></div>
<div class="announce">{announce}</div>{('<a class="btn" href="'+support+'">پشتیبانی</a>') if support else ''}</div><script>function copyText(id){{navigator.clipboard.writeText(document.getElementById(id).textContent.trim()).then(()=>alert('کپی شد'))}}</script></body></html>'''
    raw=page.encode(); h.send_response(200); h.send_header('Content-Type','text/html; charset=utf-8'); h.send_header('Cache-Control','no-store'); h.send_header('Content-Length',str(len(raw))); h.end_headers(); h.wfile.write(raw)

def qr_svg(h,sid):
    try:
        import qrcode
        from qrcode.image.svg import SvgPathImage
        s,rows=load_sub(h,sid)
        if not rows:return send(h,404,{'error':'not found'})
        link=link_for(h,rows[0],s)
        qr=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,box_size=8,border=2); qr.add_data(link); qr.make(fit=True)
        img=qr.make_image(image_factory=SvgPathImage); out=io.BytesIO(); img.save(out); raw=out.getvalue()
        h.send_response(200); h.send_header('Content-Type','image/svg+xml'); h.send_header('Cache-Control','no-store'); h.send_header('Content-Length',str(len(raw))); h.end_headers(); h.wfile.write(raw)
    except Exception as e: send(h,500,{'error':str(e)})

class H(BaseHTTPRequestHandler):
    def log_message(self,fmt,*a): print(fmt%a,flush=True)
    def do_HEAD(self):
        u=urllib.parse.urlparse(self.path); p=u.path
        if p.startswith('/sub/'):
            sid=p.split('/')[-1]; s,rows=load_sub(self,sid)
            if not rows:self.send_response(404); self.end_headers(); return
            r=rows[0]; tr=traffic_for(r['id']); total=int(float(r['gb'])*1024**3); exp=r['expiry_at']; self.send_response(200); self.send_header('Subscription-Userinfo',f'upload={tr["upload"]}; download={tr["download"]}; total={total}; expire={exp}'); self.send_header('Profile-Title',base64.b64encode(s.get('panel_title','vpnstan').encode()).decode()); self.send_header('Profile-Update-Interval',s.get('update_interval','6')); self.end_headers(); return
        self.send_response(404); self.end_headers()
    def do_GET(self):
        u=urllib.parse.urlparse(self.path); p=u.path; q=urllib.parse.parse_qs(u.query)
        if p in ('/health','/api/health'): return send(self,200,{'ok':True,'name':'vpnstan','independent':True,'xray': bool(XRAY_PROC and XRAY_PROC.poll() is None)})
        if p.startswith('/sub/'):
            sid=p.split('/')[-1]
            if q.get('html')==['1'] or 'text/html' in self.headers.get('Accept',''):
                return sub_page(self,sid)
            s,rows=load_sub(self,sid); links=[link_for(self,r,s) for r in rows]; enc=base64.b64encode('\n'.join(links).encode()).decode(); total=sum(int(float(r['gb'])*1024**3) for r in rows); up=sum(traffic_for(r['id'])['upload'] for r in rows); down=sum(traffic_for(r['id'])['download'] for r in rows); exp=max([r['expiry_at'] for r in rows],default=0)
            raw=enc.encode(); self.send_response(200); self.send_header('Content-Type','text/plain; charset=utf-8'); self.send_header('Subscription-Userinfo',f'upload={up}; download={down}; total={total}; expire={exp}'); self.send_header('Profile-Title',base64.b64encode(s.get('panel_title','vpnstan').encode()).decode()); self.send_header('Profile-Update-Interval',s.get('update_interval','6')); self.send_header('Support-Url',s.get('support_url','')); self.send_header('Profile-Web-Page-Url',f'https://{host_for(self,s)}/{s.get("sub_path","sub").strip("/")}/{sid}?html=1'); self.send_header('Announce',base64.b64encode(s.get('announce','').encode()).decode()); self.send_header('Content-Disposition',f'inline; filename="{sid}.txt"'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw); return
        if p.startswith('/qr/'): return qr_svg(self,p.split('/')[-1])
        if p.startswith('/subjson/'):
            sid=p.split('/')[-1]; s,rows=load_sub(self,sid); out=[]; host=host_for(self,s); port=int(s.get('node_port','443'))
            for r in rows:
                proto=(r['protocol'] or 'vless')
                if proto=='vless':
                    out.append({'protocol':'vless','tag':r['name'],'settings':{'vnext':[{'address':host,'port':port,'users':[{'id':r['uuid'],'encryption':'none'}]}]},'streamSettings':{'network':'ws','security':'tls','tlsSettings':{'serverName':host},'wsSettings':{'path':s.get('ws_path','/ws')}}})
                elif proto=='vmess':
                    out.append({'protocol':'vmess','tag':r['name'],'settings':{'vnext':[{'address':host,'port':port,'users':[{'id':r['uuid'],'alterId':0,'security':'auto'}]}]},'streamSettings':{'network':'ws','security':'tls','tlsSettings':{'serverName':host},'wsSettings':{'path':s.get('vmess_path','/vmess')}}})
            return send(self,200,out)
        if p=='/api/me':
            u=current_user(self); return send(self,200,{'authenticated':bool(u),'user':({'id':u['id'],'username':u['username'],'role':u['role']} if u else None)})
        if p=='/api/admin/users':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            c=db(); rows=c.execute('SELECT id,username,role,enabled,created_at FROM panel_users ORDER BY id').fetchall(); c.close()
            return send(self,200,{'success':True,'users':[dict(r) for r in rows]})
        if p=='/api/settings':
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            return send(self,200,{'success':True,'settings':settings()})
        if p=='/api/clients':
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            s=settings(); c=db(); rows=c.execute('SELECT * FROM clients ORDER BY id DESC').fetchall(); c.close(); return send(self,200,{'success':True,'clients':[client_data(self,r,s) for r in rows]})
        if p.startswith('/api/client/'):
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            try: cid=int(p.rsplit('/',1)[1])
            except: return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            c=db(); r=c.execute('SELECT * FROM clients WHERE id=?',(cid,)).fetchone(); c.close()
            if not r:return send(self,404,{'success':False,'msg':'کاربر پیدا نشد'})
            return send(self,200,{'success':True,'client':client_data(self,r,settings())})
        if p=='/api/system':
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            alive=bool(XRAY_PROC and XRAY_PROC.poll() is None)
            try: log=open('/data/xray.log','rb').read()[-6000:].decode('utf-8','replace')
            except: log=''
            return send(self,200,{'success':True,'xray':alive,'port':int(os.environ.get('PORT','8080')),'inboundPort':XRAY_INBOUND_PORT,'log':log})
        return self.static()
    def do_POST(self):
        p=urllib.parse.urlparse(self.path).path
        if p=='/api/login':
            try:d=body(self)
            except:return send(self,400,{'success':False,'msg':'درخواست نامعتبر'})
            c=db(); r=c.execute('SELECT * FROM panel_users WHERE username=? AND enabled=1',(str(d.get('username','')).strip(),)).fetchone(); c.close()
            if r and hmac.compare_digest(r['password_hash'],hash_password(d.get('password',''))):
                t=secrets.token_urlsafe(32); SESSIONS[t]=time.time()+86400; SESSION_USERS[t]=r['id']; return send(self,200,{'success':True,'user':{'username':r['username'],'role':r['role']}},{'Set-Cookie':f'vpnstan_session={t}; Path=/; HttpOnly; SameSite=Lax'})
            return send(self,401,{'success':False,'msg':'نام کاربری یا رمز عبور اشتباه است'})
        if p=='/api/logout':
            for x in self.headers.get('Cookie','').split(';'):
                if x.strip().startswith('vpnstan_session='): SESSIONS.pop(x.strip().split('=',1)[1],None); SESSION_USERS.pop(x.strip().split('=',1)[1],None)
            return send(self,200,{'success':True},{'Set-Cookie':'vpnstan_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax'})
        if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
        if p=='/api/account/change':
            try:d=body(self); u=current_user(self); old=str(d.get('oldPassword','')); nu=str(d.get('username','')).strip(); np=str(d.get('newPassword',''))
            except:return send(self,400,{'success':False,'msg':'درخواست نامعتبر'})
            c=db(); row=c.execute('SELECT * FROM panel_users WHERE id=?',(u['id'],)).fetchone()
            if not row or not hmac.compare_digest(row['password_hash'],hash_password(old)): c.close(); return send(self,400,{'success':False,'msg':'رمز فعلی اشتباه است'})
            if len(nu)<3 or len(np)<4: c.close(); return send(self,400,{'success':False,'msg':'نام کاربری حداقل ۳ و رمز حداقل ۴ کاراکتر باشد'})
            try:
                c.execute('UPDATE panel_users SET username=?,password_hash=? WHERE id=?',(nu,hash_password(np),u['id'])); c.commit(); c.close(); return send(self,200,{'success':True,'msg':'اطلاعات ورود تغییر کرد؛ دوباره وارد شوید'})
            except sqlite3.IntegrityError: c.close(); return send(self,409,{'success':False,'msg':'این نام کاربری قبلاً وجود دارد'})
        if p=='/api/admin/users/create':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try:d=body(self); nu=str(d.get('username','')).strip(); np=str(d.get('password','')); role=str(d.get('role','user'))
            except:return send(self,400,{'success':False,'msg':'درخواست نامعتبر'})
            if len(nu)<3 or len(np)<4 or role not in ('admin','user'): return send(self,400,{'success':False,'msg':'نام کاربری/رمز/نقش نامعتبر است'})
            c=db()
            try:c.execute('INSERT INTO panel_users(username,password_hash,role,enabled,created_at) VALUES(?,?,?,?,?)',(nu,hash_password(np),role,1,int(time.time()))); c.commit(); c.close(); return send(self,201,{'success':True})
            except sqlite3.IntegrityError:c.close(); return send(self,409,{'success':False,'msg':'این نام کاربری قبلاً وجود دارد'})
        if p.startswith('/api/admin/users/') and p.endswith('/toggle'):
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try:uid=int(p.split('/')[4])
            except:return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            if current_user(self)['id']==uid:return send(self,400,{'success':False,'msg':'نمی‌توان اکانت فعلی را غیرفعال کرد'})
            c=db(); c.execute('UPDATE panel_users SET enabled=1-enabled WHERE id=?',(uid,)); c.commit(); c.close(); return send(self,200,{'success':True})
        if p.startswith('/api/admin/users/') and p.endswith('/delete'):
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try:uid=int(p.split('/')[4])
            except:return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            if current_user(self)['id']==uid:return send(self,400,{'success':False,'msg':'اکانت فعلی را نمی‌توان حذف کرد'})
            c=db(); c.execute('DELETE FROM panel_users WHERE id=?',(uid,)); c.commit(); c.close(); return send(self,200,{'success':True})
        if p=='/api/settings':
            try:d=body(self); allowed={'node_host','node_port','ws_path','vmess_path','sub_path','panel_title','support_url','announce','update_interval','wg_endpoint','wg_server_public_key','dns_server'}
            except:return send(self,400,{'success':False,'msg':'درخواست نامعتبر'})
            if 'node_port' in d:
                try: port=int(d['node_port']); assert 1<=port<=65535
                except:return send(self,400,{'success':False,'msg':'پورت نامعتبر است'})
            for k,v in d.items():
                if k in allowed:set_setting(k,str(v).strip())
            restart_xray(); return send(self,200,{'success':True,'settings':settings()})
        if p=='/api/clients/create':
            try:
                d=body(self); name=str(d.get('name','')).strip(); gb=float(d.get('gb',0)); days=int(d.get('days',0)); protocol=str(d.get('protocol','vless')).lower(); dns_server=settings().get('dns_server','1.1.1.1')
                if protocol not in ('vless','vmess','wireguard','dns') or not name or gb<=0 or days<=0 or len(name)>80: raise ValueError
            except:return send(self,400,{'success':False,'msg':'نام، حجم و مدت را درست وارد کنید'})
            now=int(time.time()); r=(name,str(uuid.uuid4()),secrets.token_urlsafe(18),gb,days,now,now+days*86400)
            c=db(); c.execute('INSERT INTO clients(name,uuid,sub_id,gb,days,created_at,expiry_at,protocol,dns_server,wg_private_key,wg_address) VALUES(?,?,?,?,?,?,?,?,?,?,?)',r+ (protocol,dns_server,'','10.66.0.2/32')); c.commit(); row=c.execute('SELECT * FROM clients WHERE uuid=?',(r[1],)).fetchone(); c.close(); restart_xray(); return send(self,201,{'success':True,'client':client_data(self,row,settings())})
        if p.startswith('/api/clients/') and p.endswith('/toggle'):
            try:cid=int(p.split('/')[3])
            except:return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            c=db(); c.execute('UPDATE clients SET enabled=1-enabled WHERE id=?',(cid,)); c.commit(); c.close(); restart_xray(); return send(self,200,{'success':True})
        if p.startswith('/api/clients/') and p.endswith('/delete'):
            try:cid=int(p.split('/')[3])
            except:return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            c=db(); c.execute('DELETE FROM clients WHERE id=?',(cid,)); c.execute('DELETE FROM traffic WHERE client_id=?',(cid,)); c.commit(); c.close(); restart_xray(); return send(self,200,{'success':True})
        return send(self,404,{'success':False,'msg':'Not found'})
    def static(self):
        p=urllib.parse.urlparse(self.path).path
        if p in ('','/'):p='/index.html'
        if '..' in p:return send(self,400,{'error':'bad path'})
        f=os.path.join(WEB,p.lstrip('/'))
        if not os.path.isfile(f):return send(self,404,{'error':'not found'})
        mime='text/plain; charset=utf-8'
        if f.endswith('.html'):mime='text/html; charset=utf-8'
        elif f.endswith('.js'):mime='application/javascript; charset=utf-8'
        elif f.endswith('.css'):mime='text/css; charset=utf-8'
        raw=open(f,'rb').read(); self.send_response(200); self.send_header('Content-Type',mime); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)

if __name__=='__main__':
    init_db(); restart_xray(); threading.Thread(target=collector_loop,daemon=True).start(); print(f'vpnstan panel listening on 127.0.0.1:{PANEL_PORT}',flush=True); ThreadingHTTPServer(('127.0.0.1',PANEL_PORT),H).serve_forever()
