"""DropMarket backend — Flask + SQLite.
Rodar:  pip install -r requirements.txt && python app.py
Abra http://localhost:5000
"""
import base64, hashlib, json, os, re, secrets, sqlite3, time
import urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from decimal import Decimal
from functools import wraps
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, g, jsonify, redirect, request, send_from_directory
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DROPMARKET_DB", os.path.join(BASE, "dropmarket.db"))
COMISSAO = float(os.environ.get("COMISSAO", "0.14"))   # comissão do marketplace
IMPOSTO = float(os.environ.get("IMPOSTO", "0.06"))     # imposto sobre a venda
TOKEN_MAX_AGE = 7 * 24 * 3600
# Mercado Livre (credenciais ficam SÓ aqui, no servidor, via variáveis de ambiente)
ML_CLIENT_ID = os.environ.get("ML_CLIENT_ID", "")
ML_CLIENT_SECRET = os.environ.get("ML_CLIENT_SECRET", "")
ML_REDIRECT_URI = os.environ.get("ML_REDIRECT_URI", "")   # ex.: https://seu-dominio.com/api/ml/callback
ML_AUTH_HOST = os.environ.get("ML_AUTH_HOST", "https://auth.mercadolivre.com.br")
ML_API = os.environ.get("ML_API", "https://api.mercadolibre.com")
# CJ Dropshipping (a chave de API de cada loja é guardada criptografada no banco)
CJ_API = os.environ.get("CJ_API", "https://developers.cjdropshipping.com/api2.0/v1")
CJ_SANDBOX = os.environ.get("CJ_SANDBOX") == "1"   # pedidos de teste, sem cobrança nem envio real
# Rastreio de volta ao Mercado Livre (só funciona em envios por conta própria, "me1")
ML_TRACKING_SERVICE_ID = os.environ.get("ML_TRACKING_SERVICE_ID", "")  # opcional: só enviado se definido
TRACKING_URL_TEMPLATE = os.environ.get("TRACKING_URL_TEMPLATE", "https://t.17track.net/pt#nums={}")
ORDER_STATUS = ("Pago", "Processando", "Enviado", "Entregue", "Cancelado")


def load_secret():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(os.path.dirname(DB_PATH), ".secret_key")
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(path, 0o600)
    return open(path).read().strip()


app = Flask(__name__, static_folder="static", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
SECRET = load_secret()
signer = URLSafeTimedSerializer(SECRET, salt="dropmarket-auth")
fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(b"ml-tokens:" + SECRET.encode()).digest()))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  nome TEXT NOT NULL, custo INTEGER NOT NULL, preco INTEGER NOT NULL,
  estoque INTEGER NOT NULL, criado_em INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  codigo TEXT NOT NULL, product_id INTEGER, produto TEXT NOT NULL,
  qtd INTEGER NOT NULL, valor INTEGER NOT NULL, custo INTEGER NOT NULL,
  status TEXT NOT NULL, criado_em INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ml_accounts(
  user_id INTEGER PRIMARY KEY REFERENCES users(id), ml_user_id TEXT NOT NULL, nickname TEXT,
  access_enc TEXT NOT NULL, refresh_enc TEXT NOT NULL, expires_at INTEGER NOT NULL, last_sync INTEGER);
CREATE TABLE IF NOT EXISTS cj_accounts(
  user_id INTEGER PRIMARY KEY REFERENCES users(id), api_key_enc TEXT NOT NULL, access_enc TEXT NOT NULL,
  expires_at INTEGER NOT NULL, logistica TEXT, origem TEXT);
CREATE TABLE IF NOT EXISTS ml_pending(
  state TEXT PRIMARY KEY, user_id INTEGER NOT NULL, verifier TEXT NOT NULL, criado_em INTEGER NOT NULL);
"""


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as c:
        c.executescript(SCHEMA)
        # Em hospedagem nova o banco começa vazio: ADMIN_EMAIL/ADMIN_PASSWORD criam o dono e fecham o cadastro público.
        email, pw = os.environ.get("ADMIN_EMAIL", "").strip().lower(), os.environ.get("ADMIN_PASSWORD", "")
        if email and len(pw) >= 8 and not c.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            c.execute("INSERT INTO users(email,pass_hash) VALUES(?,?)", (email, generate_password_hash(pw)))
        cols = lambda t: {r[1] for r in c.execute(f"PRAGMA table_info({t})")}
        # Migração: bancos criados na versão anterior ganham as colunas novas.
        for name in ("ml_item_id", "cj_vid"):
            if name not in cols("products"):
                c.execute(f"ALTER TABLE products ADD COLUMN {name} TEXT")
        for name, ddl in (("origem", "TEXT NOT NULL DEFAULT 'manual'"), ("external_id", "TEXT"),
                          ("sem_custo", "INTEGER NOT NULL DEFAULT 0"),
                          ("envio_id", "TEXT"), ("rastreio", "TEXT"), ("itens", "TEXT"), ("cj_order_id", "TEXT"),
                          ("cj_status", "TEXT"), ("cj_rastreio", "TEXT"), ("cj_url", "TEXT"), ("cj_usd", "INTEGER"),
                          ("ml_rastreio_num", "TEXT"), ("ml_rastreio_em", "INTEGER")):
            if name not in cols("orders"):
                c.execute(f"ALTER TABLE orders ADD COLUMN {name} {ddl}")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_orders_ext ON orders(user_id,origem,external_id) "
                  "WHERE external_id IS NOT NULL")


# ---------- helpers ----------
def err(msg, code=400):
    return jsonify(error=msg), code


def to_int(v, lo, hi):
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError
    if not lo <= v <= hi:
        raise ValueError
    return v


def auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        h = request.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            return err("Faça login para continuar.", 401)
        try:
            g.uid = signer.loads(h[7:], max_age=TOKEN_MAX_AGE)["uid"]
        except SignatureExpired:
            return err("Sessão expirada. Entre novamente.", 401)
        except (BadSignature, KeyError):
            return err("Sessão inválida.", 401)
        return fn(*a, **kw)
    return wrapper


_attempts = {}  # ip -> [timestamps]; proteção simples contra força bruta


def too_many_attempts():
    now, ip = time.time(), request.remote_addr
    recent = [t for t in _attempts.get(ip, []) if now - t < 300]
    _attempts[ip] = recent
    return len(recent) >= 10


def credentials():
    d = request.get_json(silent=True) or {}
    email = str(d.get("email", "")).strip().lower()
    pw = str(d.get("senha", ""))
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 120:
        raise ValueError("E-mail inválido.")
    return email, pw


# ---------- auth ----------
@app.get("/api/status")
def status():
    has_user = db().execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
    return jsonify(precisa_cadastro=not has_user)


@app.post("/api/register")
def register():
    # Loja de um único dono: só o primeiro cadastro é aceito.
    if db().execute("SELECT 1 FROM users LIMIT 1").fetchone():
        return err("Cadastro já realizado. Use o login.", 403)
    try:
        email, pw = credentials()
    except ValueError as e:
        return err(str(e))
    if len(pw) < 8:
        return err("A senha precisa ter ao menos 8 caracteres.")
    cur = db().execute("INSERT INTO users(email,pass_hash) VALUES(?,?)",
                       (email, generate_password_hash(pw)))
    db().commit()
    return jsonify(token=signer.dumps({"uid": cur.lastrowid})), 201


@app.post("/api/login")
def login():
    if too_many_attempts():
        return err("Muitas tentativas. Aguarde alguns minutos.", 429)
    try:
        email, pw = credentials()
    except ValueError:
        return err("E-mail ou senha incorretos.", 401)
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u or not check_password_hash(u["pass_hash"], pw):
        _attempts.setdefault(request.remote_addr, []).append(time.time())
        return err("E-mail ou senha incorretos.", 401)
    return jsonify(token=signer.dumps({"uid": u["id"]}))


@app.post("/api/senha")
@auth
def change_password():
    d = request.get_json(silent=True) or {}
    u = db().execute("SELECT * FROM users WHERE id=?", (g.uid,)).fetchone()
    if not u or not check_password_hash(u["pass_hash"], str(d.get("atual", ""))):
        return err("A senha atual está incorreta.", 403)
    nova = str(d.get("nova", ""))
    if len(nova) < 8:
        return err("A nova senha precisa ter ao menos 8 caracteres.")
    db().execute("UPDATE users SET pass_hash=? WHERE id=?", (generate_password_hash(nova), g.uid))
    db().commit()
    return jsonify(ok=True)


# ---------- produtos ----------
def product_json(r):
    return {k: r[k] for k in ("id", "nome", "custo", "preco", "estoque", "ml_item_id", "cj_vid")}


def parse_product(d):
    nome = str(d.get("nome", "")).strip()
    if not 1 <= len(nome) <= 80:
        raise ValueError("Informe um nome de até 80 caracteres.")
    ml = str(d.get("ml_item_id") or "").upper().replace("-", "").strip() or None
    if ml and not re.fullmatch(r"[A-Z]{3}\d{6,14}", ml):
        raise ValueError("ID do anúncio inválido. Exemplo: MLB1234567890.")
    cj = str(d.get("cj_vid") or "").strip() or None
    if cj and not re.fullmatch(r"[A-Za-z0-9-]{6,50}", cj):
        raise ValueError("ID da variante do CJ inválido.")
    try:
        return (nome, to_int(d.get("custo"), 0, 10**9), to_int(d.get("preco"), 1, 10**9),
                to_int(d.get("estoque"), 0, 10**6), ml, cj)
    except ValueError:
        raise ValueError("Custo, preço e estoque devem ser números válidos (valores em centavos).")


@app.get("/api/products")
@auth
def list_products():
    rows = db().execute("SELECT * FROM products WHERE user_id=? ORDER BY id DESC", (g.uid,))
    return jsonify([product_json(r) for r in rows])


@app.post("/api/products")
@auth
def create_product():
    try:
        v = parse_product(request.get_json(silent=True) or {})
    except ValueError as e:
        return err(str(e))
    cur = db().execute(
        "INSERT INTO products(user_id,nome,custo,preco,estoque,ml_item_id,cj_vid,criado_em) VALUES(?,?,?,?,?,?,?,?)",
        (g.uid, *v, int(time.time())))
    db().commit()
    r = db().execute("SELECT * FROM products WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify(product_json(r)), 201


@app.put("/api/products/<int:pid>")
@auth
def update_product(pid):
    try:
        v = parse_product(request.get_json(silent=True) or {})
    except ValueError as e:
        return err(str(e))
    cur = db().execute("UPDATE products SET nome=?,custo=?,preco=?,estoque=?,ml_item_id=?,cj_vid=? WHERE id=? AND user_id=?",
                       (*v, pid, g.uid))
    db().commit()
    if not cur.rowcount:
        return err("Produto não encontrado.", 404)
    r = db().execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    return jsonify(product_json(r))


@app.delete("/api/products/<int:pid>")
@auth
def delete_product(pid):
    # Pedidos antigos guardam nome/custo próprios, então o histórico é preservado.
    db().execute("UPDATE orders SET product_id=NULL WHERE product_id=? AND user_id=?", (pid, g.uid))
    cur = db().execute("DELETE FROM products WHERE id=? AND user_id=?", (pid, g.uid))
    db().commit()
    return ("", 204) if cur.rowcount else err("Produto não encontrado.", 404)


# ---------- pedidos ----------
def order_json(r):
    d = {k: r[k] for k in ("id", "codigo", "produto", "qtd", "valor", "status", "criado_em", "origem", "sem_custo", "rastreio",
                                  "cj_order_id", "cj_status", "cj_rastreio", "cj_url", "cj_usd")}
    d["ml_informado"] = bool(r["ml_rastreio_num"]) and r["ml_rastreio_num"] == r["cj_rastreio"]
    return d


@app.get("/api/orders")
@auth
def list_orders():
    rows = db().execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 200", (g.uid,))
    return jsonify([order_json(r) for r in rows])


@app.post("/api/orders")
@auth
def create_order():
    d = request.get_json(silent=True) or {}
    try:
        pid, qtd = to_int(d.get("product_id"), 1, 10**9), to_int(d.get("qtd", 1), 1, 1000)
    except ValueError:
        return err("Escolha um produto e uma quantidade válida.")
    c = db()
    p = c.execute("SELECT * FROM products WHERE id=? AND user_id=?", (pid, g.uid)).fetchone()
    if not p:
        return err("Produto não encontrado.", 404)
    # UPDATE condicional evita estoque negativo mesmo com pedidos simultâneos.
    cur = c.execute("UPDATE products SET estoque=estoque-? WHERE id=? AND estoque>=?", (qtd, pid, qtd))
    if not cur.rowcount:
        c.rollback()
        return err(f"Estoque insuficiente (disponível: {p['estoque']}).", 409)
    n = c.execute("SELECT COUNT(*) FROM orders WHERE user_id=? AND origem='manual'", (g.uid,)).fetchone()[0]
    cur = c.execute(
        "INSERT INTO orders(user_id,codigo,product_id,produto,qtd,valor,custo,status,criado_em,itens) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)",
        (g.uid, f"#DM-{1001 + n}", pid, p["nome"], qtd, p["preco"] * qtd, p["custo"] * qtd,
         "Pago", int(time.time()), json.dumps([{"product_id": pid, "qtd": qtd}])))
    c.commit()
    r = c.execute("SELECT * FROM orders WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify(order_json(r)), 201


@app.patch("/api/orders/<int:oid>")
@auth
def update_order(oid):
    new = (request.get_json(silent=True) or {}).get("status")
    if new not in ORDER_STATUS:
        return err("Status inválido.")
    c = db()
    o = c.execute("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, g.uid)).fetchone()
    if not o:
        return err("Pedido não encontrado.", 404)
    if o["origem"] != "manual":
        return err("O status deste pedido vem do Mercado Livre e é atualizado na sincronização.", 409)
    if o["status"] == "Cancelado":
        return err("Pedido cancelado não pode ser alterado.", 409)
    if new == "Cancelado" and o["product_id"]:  # devolve ao estoque
        c.execute("UPDATE products SET estoque=estoque+? WHERE id=?", (o["qtd"], o["product_id"]))
    c.execute("UPDATE orders SET status=? WHERE id=?", (new, oid))
    c.commit()
    return jsonify(order_json(c.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()))


# ---------- Mercado Livre ----------
class MLError(Exception):
    def __init__(self, msg, status=None):
        super().__init__(msg)
        self.status = status


def http_json(method, url, form=None, token=None, headers=None, body=None, svc="Mercado Livre"):
    """Chamada HTTP simples (stdlib). Isolada para facilitar testes."""
    headers, data = {"Accept": "application/json", **(headers or {})}, None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        app.logger.warning("%s respondeu HTTP %s em %s", svc, e.code, url.split("?")[0])
        raise MLError(f"{svc} recusou a requisição.", e.code)
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise MLError(f"Não foi possível falar com {svc} agora. Tente novamente.")


def ml_token(form):
    return http_json("POST", ML_API + "/oauth/token",
                     form={**form, "client_id": ML_CLIENT_ID, "client_secret": ML_CLIENT_SECRET})


def ml_configured():
    return bool(ML_CLIENT_ID and ML_CLIENT_SECRET and ML_REDIRECT_URI)


def enc(s):
    return fernet.encrypt(s.encode()).decode()


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def save_ml_account(uid, tok, ml_user_id, nickname):
    db().execute(
        "INSERT INTO ml_accounts(user_id,ml_user_id,nickname,access_enc,refresh_enc,expires_at) VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(user_id) DO UPDATE SET ml_user_id=excluded.ml_user_id, nickname=excluded.nickname, "
        "access_enc=excluded.access_enc, refresh_enc=excluded.refresh_enc, expires_at=excluded.expires_at",
        (uid, str(ml_user_id), nickname, enc(tok["access_token"]), enc(tok["refresh_token"]),
         int(time.time()) + int(tok.get("expires_in", 21600))))
    db().commit()


def get_access_token(uid):
    """Devolve (access_token, conta). Renova sozinho; o refresh_token é de uso único, então o novo é salvo na hora."""
    a = db().execute("SELECT * FROM ml_accounts WHERE user_id=?", (uid,)).fetchone()
    if not a:
        raise MLError("Conecte sua conta do Mercado Livre primeiro.", 409)
    try:
        if a["expires_at"] - 120 > time.time():
            return fernet.decrypt(a["access_enc"].encode()).decode(), a
        tok = ml_token({"grant_type": "refresh_token",
                        "refresh_token": fernet.decrypt(a["refresh_enc"].encode()).decode()})
    except (InvalidToken, MLError) as e:
        if isinstance(e, MLError) and e.status not in (400, 401, 403):
            raise
        db().execute("DELETE FROM ml_accounts WHERE user_id=?", (uid,))
        db().commit()
        raise MLError("A conexão com o Mercado Livre expirou. Conecte novamente.", 409)
    save_ml_account(uid, tok, a["ml_user_id"], a["nickname"])
    return tok["access_token"], a


@app.get("/api/ml/status")
@auth
def ml_status():
    a = db().execute("SELECT nickname,last_sync FROM ml_accounts WHERE user_id=?", (g.uid,)).fetchone()
    return jsonify(configurado=ml_configured(), conectado=bool(a),
                   nickname=a["nickname"] if a else None, ultimo_sync=a["last_sync"] if a else None)


@app.post("/api/ml/connect")
@auth
def ml_connect():
    if not ml_configured():
        return err("Mercado Livre não configurado no servidor (ML_CLIENT_ID, ML_CLIENT_SECRET, ML_REDIRECT_URI).", 503)
    c = db()
    c.execute("DELETE FROM ml_pending WHERE criado_em<?", (int(time.time()) - 600,))
    state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(64)
    c.execute("INSERT INTO ml_pending(state,user_id,verifier,criado_em) VALUES(?,?,?,?)",
              (state, g.uid, verifier, int(time.time())))
    c.commit()
    q = urllib.parse.urlencode({
        "response_type": "code", "client_id": ML_CLIENT_ID, "redirect_uri": ML_REDIRECT_URI, "state": state,
        "code_challenge": b64url(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"})
    return jsonify(url=f"{ML_AUTH_HOST}/authorization?{q}")


@app.get("/api/ml/callback")
def ml_callback():
    # O navegador chega aqui vindo do Mercado Livre, sem o token do app: a identidade vem do `state`.
    state, code = request.args.get("state", ""), request.args.get("code", "")
    c = db()
    row = c.execute("SELECT * FROM ml_pending WHERE state=?", (state,)).fetchone()
    if row:
        c.execute("DELETE FROM ml_pending WHERE state=?", (state,))
        c.commit()
    if not row or not code or request.args.get("error") or time.time() - row["criado_em"] > 600:
        return redirect("/?ml=erro#settings")
    try:
        tok = ml_token({"grant_type": "authorization_code", "code": code,
                        "redirect_uri": ML_REDIRECT_URI, "code_verifier": row["verifier"]})
        me = http_json("GET", ML_API + "/users/me", token=tok["access_token"])
        save_ml_account(row["user_id"], tok, me.get("id") or tok["user_id"], me.get("nickname"))
    except (MLError, KeyError):
        return redirect("/?ml=erro#settings")
    return redirect("/?ml=ok#settings")


@app.delete("/api/ml/connection")
@auth
def ml_disconnect():
    db().execute("DELETE FROM ml_accounts WHERE user_id=?", (g.uid,))
    db().commit()
    return "", 204


def parse_ml_order(o):
    """Converte um pedido do ML no formato local. Só importa pedidos pagos ou cancelados."""
    status = {"paid": "Pago", "cancelled": "Cancelado"}.get(o.get("status"))
    if not status or not o.get("id"):
        return None
    items = []
    for it in o.get("order_items") or []:
        i = it.get("item") or {}
        items.append({"item_id": str(i.get("id", "")).upper(), "title": str(i.get("title", "Item")),
                      "qtd": max(int(it.get("quantity") or 1), 1)})
    if not items:
        return None
    try:
        criado = int(datetime.fromisoformat(str(o["date_created"])).timestamp())
    except (KeyError, ValueError):
        criado = int(time.time())
    ship = str((o.get("shipping") or {}).get("id") or "")
    nome = items[0]["title"][:80] + (f" (+{len(items) - 1} itens)" if len(items) > 1 else "")
    return {"ext": str(o["id"]), "status": status, "ship_id": ship if ship.isdigit() else None, "items": items, "produto": nome,
            "qtd": sum(i["qtd"] for i in items), "criado": criado,
            "valor": int(round(Decimal(str(o.get("total_amount") or 0)) * 100))}


# Status de envio do Mercado Livre -> status do app
SHIP_STATUS = {"pending": "Processando", "handling": "Processando", "ready_to_ship": "Processando",
               "shipped": "Enviado", "delivered": "Entregue", "not_delivered": "Não entregue"}
SHIP_LOOKUPS = 60  # consultas de envio por sincronização (evita estourar o limite de requisições do ML)


def fetch_shipment(token, ship_id):
    sh = http_json("GET", f"{ML_API}/shipments/{ship_id}", token=token, headers={"x-format-new": "true"})
    track = sh.get("tracking_number")
    return SHIP_STATUS.get(sh.get("status")), (str(track)[:60] if track else None)


@app.post("/api/ml/sync")
@auth
def ml_sync():
    c = db()
    try:
        token, a = get_access_token(g.uid)
    except MLError as e:
        return err(str(e), e.status if e.status in (409,) else 502)
    if a["last_sync"] and time.time() - a["last_sync"] < 20:
        return err("Sincronização recente. Aguarde alguns segundos.", 429)
    if not str(a["ml_user_id"]).isdigit():
        return err("Conta do Mercado Livre inválida. Conecte novamente.", 409)
    c.execute("UPDATE ml_accounts SET last_sync=? WHERE user_id=?", (int(time.time()), g.uid))
    c.commit()
    prods = {r["ml_item_id"]: r for r in c.execute(
        "SELECT * FROM products WHERE user_id=? AND ml_item_id IS NOT NULL", (g.uid,))}
    novos = atualizados = ignorados = envios = pendentes = com_erro = 0
    lookups_ok = True
    try:
        offset = 0
        for _ in range(5):  # até 250 pedidos por sincronização
            page = http_json("GET", f"{ML_API}/orders/search?seller={a['ml_user_id']}&sort=date_desc&limit=50&offset={offset}",
                             token=token)
            results = page.get("results") or []
            for o in results:
                p = parse_ml_order(o)
                if not p:
                    ignorados += 1
                    continue
                custo, sem, pid = 0, 0, None
                for it in p["items"]:
                    pr = prods.get(it["item_id"])
                    if pr:
                        custo += pr["custo"] * it["qtd"]
                        pid = pid or pr["id"]
                    else:
                        sem = 1
                itens = json.dumps([{"item_id": i["item_id"], "qtd": i["qtd"]} for i in p["items"]])
                ex = c.execute("SELECT id,status FROM orders WHERE user_id=? AND origem='mercadolivre' AND external_id=?",
                               (g.uid, p["ext"])).fetchone()
                keep = ex["status"] if ex and ex["status"] != "Cancelado" else "Pago"
                status, rastreio, envio_id = p["status"], None, None
                if p["status"] == "Pago":
                    status = keep
                    if keep != "Entregue" and p["ship_id"]:  # entregues não precisam ser consultadas de novo
                        if not lookups_ok or envios >= SHIP_LOOKUPS:
                            pendentes += 1
                        else:
                            envios += 1
                            try:
                                st, rastreio = fetch_shipment(token, p["ship_id"])
                                envio_id, status = p["ship_id"], st or keep
                            except MLError as e:
                                com_erro += 1
                                if e.status in (401, 429):
                                    lookups_ok = False
                if ex:
                    c.execute("UPDATE orders SET status=?,valor=?,custo=?,sem_custo=?,product_id=?,qtd=?,produto=?,"
                              "envio_id=COALESCE(?,envio_id),rastreio=COALESCE(?,rastreio),itens=? WHERE id=?",
                              (status, p["valor"], custo, sem, pid, p["qtd"], p["produto"], envio_id, rastreio, itens, ex["id"]))
                    atualizados += 1
                else:
                    c.execute("INSERT INTO orders(user_id,codigo,product_id,produto,qtd,valor,custo,status,criado_em,"
                              "origem,external_id,sem_custo,envio_id,rastreio,itens) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                              (g.uid, "ML-" + p["ext"], pid, p["produto"], p["qtd"], p["valor"], custo, status,
                               p["criado"], "mercadolivre", p["ext"], sem, envio_id, rastreio, itens))
                    novos += 1
            offset += 50
            if not results or offset >= int((page.get("paging") or {}).get("total", 0)):
                break
    except MLError as e:
        c.commit()
        return err(str(e), 502)
    c.commit()
    return jsonify(novos=novos, atualizados=atualizados, ignorados=ignorados,
                   envios_consultados=envios, envios_pendentes=pendentes, envios_com_erro=com_erro)


# ---------- CJ Dropshipping ----------
class CJError(Exception):
    pass


CJ_COUNTRIES = {"BR": "Brazil", "US": "United States", "PT": "Portugal", "AR": "Argentina", "CL": "Chile",
                "MX": "Mexico", "CO": "Colombia", "UY": "Uruguay", "PE": "Peru", "PY": "Paraguay"}


def cj_call(method, path, token=None, body=None):
    """Chama o CJ e valida o envelope {code, result, message, data}."""
    try:
        r = http_json(method, CJ_API + path, headers={"CJ-Access-Token": token} if token else None,
                      body=body, svc="o CJ")
    except MLError as e:
        raise CJError("Não foi possível falar com o CJ agora." if e.status is None
                      else f"O CJ recusou a requisição (HTTP {e.status}).")
    if not isinstance(r, dict):
        raise CJError("Resposta inesperada do CJ.")
    if r.get("result") is False or r.get("code") not in (200, None):
        raise CJError(("CJ: " + str(r.get("message") or "erro desconhecido"))[:220])
    return r.get("data") or {}


def cj_login(uid, api_key, logistica=None, origem=None):
    d = cj_call("POST", "/authentication/getAccessToken", body={"apiKey": api_key})
    token = d.get("accessToken")
    if not token:
        raise CJError("O CJ não devolveu um token de acesso.")
    try:
        exp = int(datetime.fromisoformat(str(d["accessTokenExpiryDate"])).timestamp())
    except (KeyError, ValueError):
        exp = int(time.time()) + 14 * 24 * 3600
    db().execute(
        "INSERT INTO cj_accounts(user_id,api_key_enc,access_enc,expires_at,logistica,origem) VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(user_id) DO UPDATE SET api_key_enc=excluded.api_key_enc, access_enc=excluded.access_enc, "
        "expires_at=excluded.expires_at",
        (uid, enc(api_key), enc(token), exp, logistica, origem))
    db().commit()
    return token


def get_cj_token(uid):
    a = db().execute("SELECT * FROM cj_accounts WHERE user_id=?", (uid,)).fetchone()
    if not a:
        raise CJError("Conecte sua conta do CJ primeiro.")
    try:
        if a["expires_at"] - 3600 > time.time():
            return fernet.decrypt(a["access_enc"].encode()).decode()
        return cj_login(uid, fernet.decrypt(a["api_key_enc"].encode()).decode())  # access token vale ~15 dias
    except InvalidToken:
        raise CJError("Não foi possível ler a conexão com o CJ. Conecte novamente.")


@app.get("/api/cj/status")
@auth
def cj_status():
    a = db().execute("SELECT logistica,origem FROM cj_accounts WHERE user_id=?", (g.uid,)).fetchone()
    return jsonify(conectado=bool(a), sandbox=CJ_SANDBOX,
                   logistica=(a["logistica"] if a else None) or "CJPacket Ordinary",
                   origem=(a["origem"] if a else None) or "CN")


@app.post("/api/cj/connect")
@auth
def cj_connect():
    key = str((request.get_json(silent=True) or {}).get("api_key", "")).strip()
    if not 10 <= len(key) <= 200 or re.search(r"\s", key):
        return err("Cole a chave de API do CJ (sem espaços).")
    try:
        cj_login(g.uid, key)
    except CJError as e:
        return err(str(e), 502)
    return jsonify(conectado=True), 201


@app.delete("/api/cj/connection")
@auth
def cj_disconnect():
    db().execute("DELETE FROM cj_accounts WHERE user_id=?", (g.uid,))
    db().commit()
    return "", 204


def clean(v, maxlen, label, required=True):
    v = str(v or "").strip()
    if required and not v:
        raise ValueError(f"Preencha: {label}.")
    if len(v) > maxlen:
        raise ValueError(f"{label}: no máximo {maxlen} caracteres.")
    return v


def load_order(oid):
    return db().execute("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, g.uid)).fetchone()


def resolve_items(uid, o):
    """Traduz os itens do pedido em variantes do CJ. Devolve (linhas, nomes_sem_vid)."""
    c = db()
    itens = json.loads(o["itens"]) if o["itens"] else None
    if itens is None and o["product_id"]:
        itens = [{"product_id": o["product_id"], "qtd": o["qtd"]}]
    lines, missing = [], []
    for it in itens or []:
        if "product_id" in it:
            p = c.execute("SELECT * FROM products WHERE id=? AND user_id=?", (it["product_id"], uid)).fetchone()
        else:
            p = c.execute("SELECT * FROM products WHERE user_id=? AND ml_item_id=?", (uid, it.get("item_id"))).fetchone()
        if p and p["cj_vid"]:
            lines.append({"vid": p["cj_vid"], "quantity": int(it["qtd"]), "nome": p["nome"]})
        else:
            missing.append(p["nome"] if p else str(it.get("item_id") or "item sem produto cadastrado"))
    if not itens:
        missing.append("pedido sem produto vinculado")
    return lines, missing


@app.get("/api/orders/<int:oid>/destino")
@auth
def order_destino(oid):
    """Dados para o formulário de envio ao CJ. O endereço do comprador é buscado na hora e NÃO é guardado."""
    o = load_order(oid)
    if not o:
        return err("Pedido não encontrado.", 404)
    lines, missing = resolve_items(g.uid, o)
    out = {"destino": {}, "itens": [{"nome": l["nome"], "qtd": l["quantity"]} for l in lines],
           "sem_cj": missing, "aviso": None}
    if o["origem"] == "mercadolivre" and o["envio_id"]:
        try:
            token, _ = get_access_token(g.uid)
            sh = http_json("GET", f"{ML_API}/shipments/{o['envio_id']}", token=token, headers={"x-format-new": "true"})
            d = sh.get("destination") or {}
            sa = d.get("shipping_address") or {}
            nm = lambda v: str((v.get("name") if isinstance(v, dict) else v) or "")
            ctry = sa.get("country")
            code = str((ctry.get("id") if isinstance(ctry, dict) else ctry) or "BR").upper()
            out["destino"] = {"nome": str(d.get("receiver_name") or ""), "endereco": str(sa.get("address_line") or ""),
                              "cidade": nm(sa.get("city")), "estado": nm(sa.get("state")),
                              "cep": str(sa.get("zip_code") or ""), "telefone": str(d.get("receiver_phone") or ""),
                              "pais_codigo": code if len(code) == 2 else "BR"}
            if "XXX" in out["destino"]["endereco"].upper():
                out["aviso"] = "O Mercado Livre oculta o endereço até o pagamento ser confirmado. Preencha manualmente."
        except MLError:
            out["aviso"] = "Não foi possível buscar o endereço no Mercado Livre. Preencha manualmente."
    return jsonify(out)


@app.post("/api/orders/<int:oid>/fornecedor")
@auth
def send_to_supplier(oid):
    """Cria o pedido no CJ SEM pagar (payType=3). O pagamento é feito por você, no painel do CJ."""
    c = db()
    o = load_order(oid)
    if not o:
        return err("Pedido não encontrado.", 404)
    if o["cj_order_id"]:
        return err("Este pedido já foi enviado ao CJ.", 409)
    if o["status"] == "Cancelado":
        return err("Pedido cancelado não pode ser enviado ao fornecedor.", 409)
    lines, missing = resolve_items(g.uid, o)
    if missing:
        return err("Informe o ID da variante do CJ nos produtos: " + ", ".join(missing) + ".", 409)
    d = request.get_json(silent=True) or {}
    dest = d.get("destino") or {}
    try:
        code = clean(dest.get("pais_codigo"), 2, "país (código de 2 letras)").upper()
        if not re.fullmatch(r"[A-Z]{2}", code):
            raise ValueError("País: use o código de 2 letras (ex.: BR).")
        origem = clean(d.get("origem") or "CN", 2, "país de origem").upper()
        body = {
            "orderNumber": f"DM{g.uid}-{o['id']}",
            "shippingCustomerName": clean(dest.get("nome"), 50, "nome do destinatário"),
            "shippingAddress": clean(dest.get("endereco"), 500, "endereço"),
            "shippingCity": clean(dest.get("cidade"), 50, "cidade"),
            "shippingProvince": clean(dest.get("estado"), 50, "estado"),
            "shippingZip": clean(dest.get("cep"), 20, "CEP", False),
            "shippingPhone": clean(dest.get("telefone"), 20, "telefone", False),
            "taxId": clean(dest.get("cpf"), 20, "CPF", False),
            "shippingCountryCode": code, "shippingCountry": CJ_COUNTRIES.get(code, code),
            "logisticName": clean(d.get("logistica"), 50, "logística"),
            "fromCountryCode": origem,
            "payType": 3,
            "products": [{"vid": l["vid"], "quantity": l["quantity"]} for l in lines],
        }
    except ValueError as e:
        return err(str(e))
    if CJ_SANDBOX:
        body["isSandbox"] = 1
    # "reserva" o pedido para impedir envio duplicado por duplo clique
    if not c.execute("UPDATE orders SET cj_order_id='pending' WHERE id=? AND cj_order_id IS NULL", (oid,)).rowcount:
        return err("Este pedido já está sendo enviado ao CJ.", 409)
    c.commit()
    try:
        data = cj_call("POST", "/shopping/order/createOrderV2", get_cj_token(g.uid), body)
    except CJError as e:
        c.execute("UPDATE orders SET cj_order_id=NULL WHERE id=?", (oid,))
        c.commit()
        return err(str(e), 502)
    try:
        usd = int(round(Decimal(str(data.get("orderAmount"))) * 100)) if data.get("orderAmount") not in (None, "") else None
    except ArithmeticError:
        usd = None
    c.execute("UPDATE orders SET cj_order_id=?,cj_status=?,cj_usd=? WHERE id=?",
              (str(data.get("orderId") or body["orderNumber"]), str(data.get("orderStatus") or "CREATED")[:30], usd, oid))
    c.execute("UPDATE cj_accounts SET logistica=?,origem=? WHERE user_id=?", (body["logisticName"], origem, g.uid))
    c.commit()
    return jsonify(order_json(load_order(oid))), 201


@app.post("/api/orders/<int:oid>/rastreio-ml")
@auth
def send_tracking_to_ml(oid):
    """Informa ao Mercado Livre o rastreio do CJ (marca o pedido como enviado para o comprador).
    Só vale para envios por conta própria (mode "me1"); no Mercado Envios o rastreio é controlado pelo ML."""
    c = db()
    o = load_order(oid)
    if not o:
        return err("Pedido não encontrado.", 404)
    if o["origem"] != "mercadolivre" or not o["envio_id"]:
        return err("Só é possível informar rastreio de pedidos importados do Mercado Livre que tenham envio.", 409)
    track = o["cj_rastreio"]
    if not track or o["cj_status"] not in ("SHIPPED", "DELIVERED"):
        return err("O CJ ainda não enviou este pedido (sem código de rastreio). Atualize o status do CJ e tente de novo.", 409)
    if o["ml_rastreio_num"] == track:
        return err("Este rastreio já foi informado ao Mercado Livre.", 409)
    try:
        token, _ = get_access_token(g.uid)
        sh = http_json("GET", f"{ML_API}/shipments/{o['envio_id']}", token=token)
        mode = sh.get("mode") or (sh.get("logistic") or {}).get("mode")
        if mode and mode != "me1":
            return err(f"Este envio usa o Mercado Envios (modo {mode}): o rastreio é controlado pelo Mercado Livre "
                       "e não pode ser informado por aqui. Só vale para anúncios com envio por conta própria.", 409)
        url = o["cj_url"] or TRACKING_URL_TEMPLATE.format(urllib.parse.quote(track, safe=""))
        payload = {"comment": "despachado", "date": datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")}
        if ML_TRACKING_SERVICE_ID:
            payload["service_id"] = int(ML_TRACKING_SERVICE_ID) if ML_TRACKING_SERVICE_ID.isdigit() else ML_TRACKING_SERVICE_ID
        http_json("POST", f"{ML_API}/shipments/{o['envio_id']}/seller_notifications", token=token,
                  body={"payload": payload, "tracking_number": track, "tracking_url": url,
                        "status": "shipped", "substatus": "null"})
    except MLError as e:
        if e.status in (400, 403, 404, 409, 422):
            return err("O Mercado Livre recusou o rastreio. Confira se o pedido usa envio por conta própria "
                       f"(e se falta configurar ML_TRACKING_SERVICE_ID). Código HTTP {e.status}.", 502)
        return err(str(e), 502)
    c.execute("UPDATE orders SET ml_rastreio_num=?, ml_rastreio_em=?, status='Enviado' WHERE id=?",
              (track, int(time.time()), oid))
    c.commit()
    return jsonify(order_json(load_order(oid)))


@app.post("/api/cj/sync")
@auth
def cj_sync():
    c = db()
    try:
        token = get_cj_token(g.uid)
    except CJError as e:
        return err(str(e), 409)
    rows = c.execute("SELECT id,cj_order_id,cj_status FROM orders WHERE user_id=? AND cj_order_id IS NOT NULL "
                     "AND cj_order_id!='pending' AND COALESCE(cj_status,'') NOT IN ('DELIVERED','CANCELLED') LIMIT 40",
                     (g.uid,)).fetchall()
    ok = erros = 0
    for r in rows:
        try:
            d = cj_call("GET", "/shopping/order/getOrderDetail?orderId=" + urllib.parse.quote(r["cj_order_id"], safe=""), token)
        except CJError:
            erros += 1
            continue
        url = d.get("trackingUrl")
        url = url if isinstance(url, str) and re.match(r"https?://", url) and len(url) <= 300 else None
        try:
            usd = int(round(Decimal(str(d["orderAmount"])) * 100)) if d.get("orderAmount") not in (None, "") else None
        except (ArithmeticError, KeyError):
            usd = None
        track = str(d["trackNumber"])[:60] if d.get("trackNumber") else None
        c.execute("UPDATE orders SET cj_status=?,cj_rastreio=COALESCE(?,cj_rastreio),cj_url=COALESCE(?,cj_url),"
                  "cj_usd=COALESCE(?,cj_usd) WHERE id=?",
                  (str(d.get("orderStatus") or r["cj_status"] or "")[:30], track, url, usd, r["id"]))
        ok += 1
    c.commit()
    return jsonify(atualizados=ok, erros=erros)


# ---------- dashboard ----------
@app.get("/api/dashboard")
@auth
def dashboard():
    c = db()
    rows = c.execute("SELECT valor,custo,sem_custo,status FROM orders WHERE user_id=? AND status!='Cancelado'", (g.uid,)).fetchall()
    fat = sum(r["valor"] for r in rows)
    lucro = sum(r["valor"] - r["custo"] - round(r["valor"] * COMISSAO) - round(r["valor"] * IMPOSTO) for r in rows)
    prods = c.execute("SELECT COUNT(*) FROM products WHERE user_id=?", (g.uid,)).fetchone()[0]
    return jsonify(faturamento=fat, pedidos=len(rows), lucro=lucro, produtos=prods,
                   pedidos_sem_custo=sum(1 for r in rows if r["sem_custo"]),
                   a_enviar=sum(1 for r in rows if r["status"] in ("Pago", "Processando")),
                   em_transito=sum(1 for r in rows if r["status"] == "Enviado"),
                   comissao=COMISSAO, imposto=IMPOSTO)


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "*")


@app.before_request
def preflight():
    if request.method == "OPTIONS" and request.path.startswith("/api/"):
        return "", 204


@app.after_request
def headers(r):
    if request.path.startswith("/api/"):
        r.headers["Access-Control-Allow-Origin"] = CORS_ORIGIN
        r.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        r.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        r.headers["Cache-Control"] = "no-store"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return r


init_db()
if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)), debug=False)
