from flask import Flask, request, jsonify, send_from_directory, redirect, session
from flask_cors import CORS
from groq import Groq
import bcrypt, jwt, sqlite3, os, tempfile, base64, json, secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
import urllib.parse, urllib.request

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = secrets.token_hex(32)

GROQ_KEY     = os.getenv("GROQ_KEY")
JWT_SECRET   = os.getenv("JWT_SECRET", "voidx_key")
STRIPE_KEY   = "sk_test_YOUR_STRIPE_KEY_HERE"
PRICE_ID     = "price_YOUR_PRICE_ID_HERE"
BASE_DIR     = "/home/kara/VOIDX"
DB_PATH      = os.path.join(BASE_DIR, "voidx.db")
FREE_LIMIT   = 50

GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI  = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:5000/auth/google/callback")

client = Groq(api_key=GROQ_KEY)
SYSTEM_PROMPT = "You are VOIDX, an advanced AI assistant. Detect the language and always respond in the same language. You are powerful, precise and friendly. Never mention Groq or any platform."
conversations = {}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT    UNIQUE NOT NULL,
            password    TEXT,
            plan        TEXT    DEFAULT 'free',
            google_id   TEXT,
            stripe_id   TEXT,
            created_at  TEXT    DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS usage (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            date        TEXT    NOT NULL,
            count       INTEGER DEFAULT 0,
            UNIQUE(user_id, date),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    conn.commit()
    conn.close()
    print("Veritabani hazir")

init_db()

def make_token(user_id, email):
    payload = {"user_id": user_id, "email": email, "exp": datetime.now(timezone.utc) + timedelta(days=30)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Giris yapmaniz gerekiyor"}), 401
        request.user = payload
        return f(*args, **kwargs)
    return decorated

def get_today_usage(user_id):
    today = datetime.now().strftime("%Y-%m-%d")
    conn = get_db()
    row = conn.execute("SELECT count FROM usage WHERE user_id=? AND date=?", (user_id, today)).fetchone()
    conn.close()
    return row["count"] if row else 0

def increment_usage(user_id):
    today = datetime.now().strftime("%Y-%m-%d")
    conn = get_db()
    conn.execute("INSERT INTO usage (user_id, date, count) VALUES (?, ?, 1) ON CONFLICT(user_id, date) DO UPDATE SET count = count + 1", (user_id, today))
    conn.commit()
    conn.close()

def get_user_plan(user_id):
    conn = get_db()
    row = conn.execute("SELECT plan FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return row["plan"] if row else "free"

# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.route("/auth/register", methods=["POST"])
def register():
    data = request.json or {}
    email = data.get("email", "").strip().lower()
    pw = data.get("password", "")
    if not email or "@" not in email:
        return jsonify({"error": "Gecerli bir email gir"}), 400
    if len(pw) < 6:
        return jsonify({"error": "Sifre en az 6 karakter olmali"}), 400
    hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    try:
        conn = get_db()
        cur = conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed))
        user_id = cur.lastrowid
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Bu email zaten kayitli"}), 409
    token = make_token(user_id, email)
    return jsonify({"token": token, "user": {"id": user_id, "email": email, "plan": "free"}}), 201

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email", "").strip().lower()
    pw = data.get("password", "")
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not user or not user["password"] or not bcrypt.checkpw(pw.encode(), user["password"].encode()):
        return jsonify({"error": "Email veya sifre hatali"}), 401
    token = make_token(user["id"], user["email"])
    return jsonify({"token": token, "user": {"id": user["id"], "email": user["email"], "plan": user["plan"]}})

@app.route("/auth/me", methods=["GET"])
@require_auth
def me():
    uid = request.user["user_id"]
    conn = get_db()
    user = conn.execute("SELECT id, email, plan FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    usage = get_today_usage(uid)
    return jsonify({"id": user["id"], "email": user["email"], "plan": user["plan"], "usage_today": usage, "limit": FREE_LIMIT if user["plan"] == "free" else None})

# ── GOOGLE OAUTH ──────────────────────────────────────────────────────────────
@app.route("/auth/google")
def google_login():
    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state
    params = urllib.parse.urlencode({
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope":         "openid email profile",
        "state":         state,
        "access_type":   "offline",
        "prompt":        "select_account"
    })
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?{params}")

@app.route("/auth/google/callback")
def google_callback():
    code  = request.args.get("code")
    state = request.args.get("state")

    if not code:
        return redirect("/auth.html?error=google_cancelled")

    # Token al
    try:
        token_data = urllib.parse.urlencode({
            "code":          code,
            "client_id":     GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri":  GOOGLE_REDIRECT_URI,
            "grant_type":    "authorization_code"
        }).encode()

        req = urllib.request.Request(
            "https://oauth2.googleapis.com/token",
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        with urllib.request.urlopen(req) as res:
            tokens = json.loads(res.read())

        # Kullanıcı bilgisi al
        user_req = urllib.request.Request(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        with urllib.request.urlopen(user_req) as res:
            guser = json.loads(res.read())

        email     = guser["email"].lower()
        google_id = guser["id"]

        # DB'de kullanıcı bul veya oluştur
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user:
            conn.execute("UPDATE users SET google_id=? WHERE id=?", (google_id, user["id"]))
            conn.commit()
            user_id = user["id"]
            plan    = user["plan"]
        else:
            cur = conn.execute("INSERT INTO users (email, google_id) VALUES (?, ?)", (email, google_id))
            user_id = cur.lastrowid
            plan    = "free"
            conn.commit()
        conn.close()

        token = make_token(user_id, email)
        user_json = urllib.parse.quote(json.dumps({"id": user_id, "email": email, "plan": plan}))
        return redirect(f"/auth.html?token={token}&user={user_json}")

    except Exception as e:
        print("Google OAuth error:", e)
        return redirect("/auth.html?error=google_failed")

# ── STRIPE ────────────────────────────────────────────────────────────────────
@app.route("/stripe/checkout", methods=["POST"])
@require_auth
def stripe_checkout():
    try:
        import stripe
        stripe.api_key = STRIPE_KEY
        uid   = request.user["user_id"]
        email = request.user["email"]
        session_obj = stripe.checkout.Session.create(
            payment_method_types=["card"], mode="subscription", customer_email=email,
            line_items=[{"price": PRICE_ID, "quantity": 1}],
            success_url="http://localhost:5000/stripe/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url="http://localhost:5000/index.html",
            metadata={"user_id": uid}
        )
        return jsonify({"url": session_obj.url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/stripe/success", methods=["GET"])
def stripe_success():
    sid = request.args.get("session_id")
    try:
        import stripe
        stripe.api_key = STRIPE_KEY
        s = stripe.checkout.Session.retrieve(sid)
        uid = s.metadata.get("user_id")
        if uid:
            conn = get_db()
            conn.execute("UPDATE users SET plan='premium', stripe_id=? WHERE id=?", (s.customer, int(uid)))
            conn.commit()
            conn.close()
    except Exception as e:
        print("Stripe success error:", e)
    return send_from_directory(BASE_DIR, "index.html")

# ── CHAT ──────────────────────────────────────────────────────────────────────
@app.route("/chat", methods=["POST"])
@require_auth
def chat():
    uid  = request.user["user_id"]
    plan = get_user_plan(uid)
    if plan == "free" and get_today_usage(uid) >= FREE_LIMIT:
        return jsonify({"error": "limit_reached", "message": "Gunluk 50 mesaj hakkin doldu!"}), 429
    data    = request.json or {}
    message = data.get("message", "")
    sid     = data.get("session_id", f"user_{uid}")
    if sid not in conversations:
        conversations[sid] = []
    conversations[sid].append({"role": "user", "content": message})
    history = conversations[sid][-20:]
    try:
        r = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "system", "content": SYSTEM_PROMPT}] + history,
            max_tokens=2048, temperature=0.7
        )
        reply = r.choices[0].message.content
        conversations[sid].append({"role": "assistant", "content": reply})
        increment_usage(uid)
        return jsonify({"response": reply})
    except Exception as e:
        return jsonify({"response": str(e)}), 500

@app.route("/upload", methods=["POST"])
@require_auth
def upload():
    uid = request.user["user_id"]
    if get_user_plan(uid) == "free" and get_today_usage(uid) >= FREE_LIMIT:
        return jsonify({"response": "Gunluk limitin doldu!"}), 429
    try:
        data = request.json
        content  = data.get("content", "")
        filename = data.get("filename", "file")
        sid      = data.get("session_id", f"user_{uid}")
        prompt   = f"Kullanici '{filename}' adli bir dosya yukledi. Icerik:\n\n{content[:8000]}\n\nAnaliz et, ozetle."
        if sid not in conversations:
            conversations[sid] = []
        conversations[sid].append({"role": "user", "content": prompt})
        r = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "system", "content": SYSTEM_PROMPT}] + conversations[sid][-10:],
            max_tokens=2048
        )
        reply = r.choices[0].message.content
        conversations[sid].append({"role": "assistant", "content": reply})
        increment_usage(uid)
        return jsonify({"response": reply})
    except Exception as e:
        return jsonify({"response": str(e)}), 500

@app.route("/reset", methods=["POST"])
def reset():
    sid = request.json.get("session_id", "default")
    conversations[sid] = []
    return jsonify({"status": "ok"})

@app.route("/save_history", methods=["POST"])
def save_history():
    try:
        msgs = request.json.get("messages", [])
        with open(os.path.join(BASE_DIR, "history.json"), "w") as f:
            json.dump(msgs, f, ensure_ascii=False)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)})

@app.route("/load_history", methods=["GET"])
def load_history():
    try:
        with open(os.path.join(BASE_DIR, "history.json"), "r") as f:
            msgs = json.load(f)
        return jsonify({"messages": msgs})
    except:
        return jsonify({"messages": []})

@app.route("/transcribe", methods=["POST"])
def transcribe():
    try:
        data = request.json
        audio_b64 = data.get("audio", "")
        lang = data.get("lang", "tr")
        audio_bytes = base64.b64decode(audio_b64)
        with tempfile.NamedTemporaryFile(suffix=".webm", delete=False) as f:
            f.write(audio_bytes)
            tmp_path = f.name
        with open(tmp_path, "rb") as f:
            transcription = client.audio.transcriptions.create(
                file=("audio.webm", f, "audio/webm"),
                model="whisper-large-v3", language=lang, response_format="text"
            )
        os.unlink(tmp_path)
        return jsonify({"text": transcription})
    except Exception as e:
        return jsonify({"text": "", "error": str(e)}), 500

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "auth.html")

@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(BASE_DIR, filename)

if __name__ == "__main__":
    print("\n VOIDX v5.0 baslatiliyor...")
    print("   http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
