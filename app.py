from urllib import request
from flask import Flask, jsonify, request, Response
from flask_api import status
import psycopg2
import os
from dotenv import load_dotenv
from flask_jwt import JWT, jwt_required, current_identity
import jwt
from flask_cors import CORS, cross_origin
from datetime import datetime, timedelta, timezone


load_dotenv()
app = Flask(__name__)
CORS(app)

app.config["CORS_HEADERS"] = "Content-Type"
CORS(app, resources={r"/*": {"origins": "*"}})


conn = psycopg2.connect(os.environ.get("FLASK_DB_URI", ""))

conn.autocommit = True
db = conn.cursor()

# Test if music db exist
db.execute(
    """SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';"""
)

resp = db.fetchall()
resp = list(map(lambda r: r[0], resp))

if "musics" not in resp:
    db.execute(
        """CREATE TABLE musics ( 
              id SERIAL PRIMARY KEY,
              name TEXT NOT NULL,
              category TEXT NOT NULL,
              vocal TEXT NOT NULL,
              language TEXT NOT NULL,
              serie TEXT,
              artist TEXT
             );"""
    )

# Test if users db exist
db.execute(
    """SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';"""
)

resp = db.fetchall()
resp = list(map(lambda r: r[0], resp))

if "users" not in resp:
    db.execute(
        """CREATE TABLE users ( 
              id SERIAL PRIMARY KEY,
              login TEXT NOT NULL UNIQUE,
              password TEXT NOT NULL
             );"""
    )
    db.execute(
        """INSERT INTO users (login, password) VALUES (
        %s, crypt(%s, gen_salt('bf'))
      );""",
        (os.getenv("DEFAULT_USER"), os.getenv("DEFAULT_PASSWORD")),
    )


def jwt_encode(data):
    return jwt.encode(data, os.getenv("JWT_SECRET"), algorithm="HS256")


def jwt_decode(jwt_token, leeway=0):
    return jwt.decode(
        jwt_token, os.getenv("JWT_SECRET"), algorithms=["HS256"], leeway=leeway
    )


music_default_dict = {
    "name": "",
    "serie": "",
    "artist": "",
    "language": "",
    "vocal": "",
    "category": "",
}


def create_music(data):
    if not all([data.get(item, False) for item in music_default_dict.keys()]):
        return (
            jsonify(
                {
                    "error": "Invalid or missing data for music creation. Please refer to the documentation."
                }
            ),
            status.HTTP_400_BAD_REQUEST,
        )
    db.execute(
        """INSERT INTO musics (name, serie, artist, language, vocal, category) VALUES (%s,%s,%s,%s,%s,%s)""",
        (
            data["name"],
            data["serie"],
            data["artist"],
            data["language"],
            data["vocal"],
            data["category"],
        ),
    )


def check_auth_error(json):
    if not json["jwt_token"]:
        return (
            jsonify({"error": "Authentication needed."}),
            status.HTTP_401_UNAUTHORIZED,
        )
    if not karaoke_list_verify_token(json["jwt_token"]):
        return (
            jsonify({"error": "User is not authentified."}),
            status.HTTP_401_UNAUTHORIZED,
        )
    return None


# Routes

# GET
@app.get("/api/karaoke_list/musics")
def karaoke_list_get():
    db.execute(
        """SELECT name, serie, artist, language, vocal, category, id  FROM musics"""
    )
    data = db.fetchall()
    results = list(
        map(
            lambda r: {
                "name": r[0],
                "serie": r[1],
                "artist": r[2],
                "language": r[3],
                "vocal": r[4],
                "category": r[5],
                "id": r[6],
            },
            data,
        )
    )
    return jsonify(results)


# POST


@app.post("/api/karaoke_list/musics")
def karaoke_list_post():
    if not request.get_json(force=True):
        return (
            jsonify({"error": "No data provided"}),
            status.HTTP_400_BAD_REQUEST,
        )
    json = request.get_json(force=True)
    auth_error = check_auth_error(json)
    if auth_error:
        return auth_error
    if json.get("data", False):
        data: dict = json["data"]
        try:
            create_music(data)
        except Exception as e:
            return (
                jsonify({"error": e.args, "music": data}),
                status.HTTP_400_BAD_REQUEST,
            )
        return jsonify({"success": "Music created successfully"})
    elif json.get("datas", False):
        for data in json["datas"]:
            try:
                create_music(data)
            except Exception as e:
                return (
                    jsonify({"error": e.args, "music": data}),
                    status.HTTP_400_BAD_REQUEST,
                )
        return jsonify({"success": "Musics created successfully"})
    else:
        return (
            jsonify({"error": "No data provided"}),
            status.HTTP_400_BAD_REQUEST,
        )


@app.post("/api/karaoke_list/delete")
def karaoke_list_delete():
    if not request.get_json(force=True):
        return (
            jsonify({"error": "No data provided"}),
            status.HTTP_400_BAD_REQUEST,
        )
    json = request.get_json(force=True)
    auth_error = check_auth_error(json)
    if auth_error:
        return auth_error
    if not json.get("id"):
        return (
            jsonify({"error": "No id provided"}),
            status.HTTP_400_BAD_REQUEST,
        )
    else:
        db.execute("""DELETE FROM musics WHERE id = %s""", (json["id"]))


@app.post("/api/karaoke_list/auth")
def karaoke_list_auth():
    if not request.get_json(force=True):
        return (
            jsonify({"error": "No login information provided"}),
            status.HTTP_401_UNAUTHORIZED,
        )

    # Try to connect
    data = request.get_json(force=True)
    db.execute(
        """SELECT id FROM users WHERE login=%s and password=crypt(%s, password)""",
        (data["login"], data["password"]),
    )
    resp = db.fetchall()
    if resp:
        return jwt_encode(
            {
                "user_id": resp[0],
                "exp": datetime.now(tz=timezone.utc) + timedelta(hours=1),
            }
        )
    else:
        return (
            jsonify({"error": "Invalid login or password"}),
            status.HTTP_401_UNAUTHORIZED,
        )


@app.post("/api/karaoke_list/verify")
def karaoke_list_verify_token(jwt_token=""):
    # Local Request
    if not request.get_json(force=True) and jwt_token != "":
        try:
            jwt_decode(jwt_token, leeway=10)
            return True
        except Exception as e:
            return False
    try:
        return jwt_decode(request.get_json(force=True)), status.HTTP_200_OK
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "token expired"}), status.HTTP_401_UNAUTHORIZED
    except Exception as e:
        return jsonify(e.args), status.HTTP_401_UNAUTHORIZED


def identity(payload):
    user_id = payload["identity"]
    db.execute("""SELECT id FROM users WHERE id=%s""", (user_id))
    return db.fetchall()[0]


app.config["JWT_AUTH_URL_RULE"] = "/api/karaoke_list/auth"
app.config["JWT_EXPIRATION_DELTA"] = timedelta(seconds=1800)


if __name__ == "__main__":
    app.run(host="0.0.0.0")
