from flask import Flask, request, jsonify, redirect, render_template
import time
from pymongo import MongoClient
from datetime import datetime, timezone
from dotenv import load_dotenv
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import JWTManager, create_access_token, set_access_cookies, jwt_required, get_jwt_identity, unset_jwt_cookies
from datetime import timedelta
from uuid import uuid4
import string
import random

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_COOKIE_CSRF_PROTECT"] = True
jwt = JWTManager(app)
limiter = Limiter(
    get_remote_address,
    app=app
)

MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["InboxAPI"]
loginCollection = db["login"]
apiKeyCollection = db["apiKeys"]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")

@limiter.limit("5 per minute")
@app.route("/api/login", methods=["POST"])
def login():
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400
    
    if not request.json.get("username") or not request.json.get("password"):
        return jsonify({"error": "Missing username or password"}), 400
    
    username = request.json.get("username")
    password = request.json.get("password")

    user = loginCollection.find_one({"username": username})
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(
        identity=user["username"],
        expires_delta=timedelta(hours=24),
        additional_claims={
            "username": user["username"],            
        }
    )
    
    response = jsonify({"status": "ok"})
    
    set_access_cookies(response, access_token)
    
    return response, 200

@limiter.limit("60 per minute")
@app.route("/api/@me", methods=["GET"])
@jwt_required()
def me():
    current_username = get_jwt_identity()
    
    user = loginCollection.find_one({"username": current_username})
    if not user:
        return jsonify({"error": "User not found"}), 404

    apiKeyDoc = apiKeyCollection.find_one({"apikey": user["apikey"]})
    namespaces = apiKeyDoc.get("namespaces", []) if apiKeyDoc else []

    return jsonify({
        "username": user["username"],
        "apikey": user["apikey"],
        "namespaces": namespaces
    })

@limiter.limit("3 per minute")
@app.route("/api/register", methods=["POST"])
def register():
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    if loginCollection.find_one({"username": username}):
        return jsonify({"error": "User already exists"}), 400

    hashed_password = generate_password_hash(password)
    apikey = str(uuid4())
    loginCollection.insert_one({
        "username": username,
        "password": hashed_password,
        "apikey": apikey
    })

    while True:
        namespace = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(5))
        if not apiKeyCollection.find_one({"namespace": namespace}):
            break

    apiKeyCollection.insert_one({
        "apikey": apikey,
        "namespaces": [namespace],
    })

    response = jsonify({"status": "ok"})

    access_token = create_access_token(
        identity=username,
        expires_delta=timedelta(hours=24),
        additional_claims={
            "username": username,
        }
    )
    set_access_cookies(response, access_token)

    return response

@app.route("/api/logout", methods=["POST"])
@jwt_required()
def logout():
    response = jsonify({"status": "ok"})
    unset_jwt_cookies(response)
    return response

@app.route("/internal/receive_mail/<namespace>", methods=["POST"])
def receive_email(namespace):
    data = request.json
    if not data or "to" not in data:
        return jsonify({"error": "Invalid payload"}), 400

    if len(namespace) != 5 or not namespace.islower():
        return jsonify({"error": "Namespace doesn't exist"}), 400

    if not apiKeyCollection.find_one({"namespaces": namespace}):
        return jsonify({"error": "Namespace doesn't exist"}), 400

    try:
        local_part = data["to"].split("@")[0]
        _, tag = local_part.split(".")
    except Exception:
        return jsonify({"error": "Invalid email format"}), 400

    email_doc = {
        "to": data["to"],
        "from": data.get("from"),
        "subject": data.get("subject", "").strip(),
        "text": data.get("text", "").strip(),
        "html": data.get("html", "").strip(),
        "attachments": data.get("attachments", []),
        "tag": tag,
        "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000),
        "id": data.get("id", None),
        "envelope_from": data.get("envelope_from", None),
        "envelope_to": data.get("to"),
        "from_parsed": data.get("from_parsed", [{"address": data.get("from"), "name": ""}]),
        "cc": data.get("cc", ""),
        "cc_parsed": data.get("cc_parsed", []),
        "dkim": data.get("dkim", "none"),
        "SPF": data.get("SPF", "pass"),
    }

    collection = db[namespace]
    collection.insert_one(email_doc)

    return jsonify({"status": "success"}), 200

@app.route("/api/json", methods=["GET"])
def fetch_emails():
    api_key = request.args.get("apikey")
    if not api_key:
        return jsonify({"error": "Unauthorized"}), 401

    if not apiKeyCollection.find_one({"apikey": api_key}):
        return jsonify({"error": "Invalid API key"}), 401

    namespace = request.args.get("namespace")
    tag = request.args.get("tag")
    after = request.args.get("after")
    live = request.args.get("live", "false").lower() == "true"
    limit = int(request.args.get("limit", 10))
    offset = int(request.args.get("offset", 0))

    if not namespace:
        return jsonify({"error": "Namespace is required"}), 400

    if len(namespace) != 5 or not namespace.islower():
        return jsonify({"error": "Invalid namespace"}), 400

    if not apiKeyCollection.find_one({"namespaces": namespace, "apikey": api_key}):
        return jsonify({"error": "Namespace doesn't exist"}), 400

    collection = db[namespace]

    query = {}
    if tag:
        query["tag"] = tag
    if after:
        try:
            after_ts = int(after)
            query["timestamp"] = {"$gt": after_ts}
        except ValueError:
            return jsonify({"error": "Invalid 'after' timestamp"}), 400

    def get_emails():
        cursor = (
            collection.find(query, {"_id": 0})
            .sort("timestamp", -1)
            .skip(offset)
            .limit(limit)
        )
        return list(cursor)

    if not live:
        emails = get_emails()
        total_count = collection.count_documents(query)
        return jsonify({
            "result": "success",
            "message": None,
            "count": total_count,
            "limit": limit,
            "offset": offset,
            "emails": emails
        })

    start_time = int(datetime.now(timezone.utc).timestamp() * 1000)
    poll_after = start_time

    while True:
        poll_query = dict(query)
        poll_query["timestamp"] = {"$gt": poll_after}

        emails = (
            collection.find(poll_query, {"_id": 0})
            .sort("timestamp", -1)
            .limit(limit)
        )
        emails = list(emails)

        if emails:
            total_count = collection.count_documents(poll_query)
            return jsonify({
                "result": "success",
                "message": None,
                "count": total_count,
                "limit": limit,
                "offset": 0,
                "emails": emails
            })

        if int(time.time()) - start_time >= 15:
            return redirect(request.url, code=302)

        time.sleep(1)

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": str(e.description)
    }), 429

if __name__ == "__main__":
    app.run()

