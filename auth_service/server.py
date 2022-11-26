import jwt, datetime, os
from flask import Flask, request
from flask_mysqldb import MySQL
import json

server = Flask(__name__)
mysql = MySQL(server)

# Load config
file_config = open("auth_config.json")
config_json = json.load(file_config)
file_config.close()
print("Load Config Success")

# config
server.config['MYSQL_HOST'] = config_json["mysql_host"]
server.config['MYSQL_USER'] = config_json["mysql_user"]
server.config['MYSQL_PASSWORD'] = config_json["mysql_password"]
server.config['MYSQL_DB'] = config_json["mysql_db"]
server.config['MYSQL_PORT'] = config_json["mysql_port"]

@server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "Missing credentials", 401
    
    # check db for username and password
    cur = mysql.connection.cursor()
    res = cur.execute(
        "select * from user"
    )
    if res > 0:
        user_row = cur.fetchone()
        email = user_row[0]
        password = user_row[1]

        if auth.username != email or auth.password != password:
            return "invalid credentials", 401
        else:
            # Create JWT
            return creatJWT(auth.username, config_json["jwt_secret"], True)

    else:
        return "Invalid credentials", 401

def creatJWT(username, secret, authz):

    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1),
            'iat': datetime.datetime.utcnow(),
            "admin": authz
        },
        secret,
        algorithm="HS256"
    )

@server.route("/validate", method=["POST"])
def validate():
    encode_jwt = request.headers["Authorization"]

    if not encode_jwt:
        return "Missing credentials", 401

    encode_jwt = encode_jwt.split(" ")[1]

    try:
        decoded = jwt.decode(
            encode_jwt, config_json["jwt_secret"], algorithms=["HS256"]
        )
    except:
        return "Not Authorized", 403

    return decoded, 200
    
if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)