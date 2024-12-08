from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import json
import sqlite3
import datetime
import jwt
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher


#Please note I did my best to lint
#used VS code Pylint
#didn't know what a docstring meant so I used chatgpt
#used prompt "What is a docstring in python"

#sets host and server port
HOSTNAME = "localhost"
SERVERPORT = 8080

#generates RSA encryption/decryption keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

#pem encryption being set
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()

#used chatgpt with the prompts "SQL backed storage table schema in python" andh>
def create_open_db(db_name):
    """Creates a DB file"""
    #create or opens a db file
    connect = sqlite3.connect(db_name)
    print("Database Created")
    #creates table
    cursor = connect.cursor()
    create_table_key = """CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
    );
    """
    create_table_people = """CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP      
    );
    """
    create_table_auth = """CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,  
    FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """
    cursor.execute(create_table_key)
    cursor.execute(create_table_people)
    cursor.execute(create_table_auth)
    connect.commit()
    connect.close()
    return connect

def store_private_key(db_name, key, exp):
    """Storing private keys"""
    connect = sqlite3.connect(db_name)
    cursor = connect.cursor()
    cursor.execute("""INSERT INTO keys(key, exp) VALUES (?, ?);""", (key, exp))
    connect.commit()
    print("Key Stored")
    connect.close()

#used chatgpt by using the prompt with all the requirements for user tables
def store_person(db_name, uname, email, p_hash):
    """Storing users with hashing for passwords"""
    connect = sqlite3.connect(db_name)
    cursor = connect.cursor()
    cursor.execute("""INSERT INTO users(username, email, password_hash) VALUES (?, ?, ?);""", (uname, email, p_hash))
    connect.commit()
    print("Person is Entered")
    connect.close()

def get_private_key(db_name, exp=False):
    """Gets private keys"""
    connect = sqlite3.connect(db_name)
    cursor = connect.cursor()
    curr_time = int(datetime.datetime.utcnow().timestamp())
    if exp:
        cursor.execute("SELECT key FROM keys WHERE exp < ? LIMIT 1;", (curr_time,))
    else:
        cursor.execute("SELECT key FROM keys WHERE exp > ? LIMIT 1;", (curr_time,))
    key_row = cursor.fetchone()
    connect.close()
    if key_row:
        return key_row[0]
    else:
        return None

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

#Used ChatGPT prompt "How to read all valid (non-expired) keys from DB and create a JWKS response from those keys"
def get_valid_keys(db_name):
    """Get all valid private keys that are not expired"""
    connect = sqlite3.connect(db_name)
    cursor = connect.cursor()
    cursor.execute("SELECT key FROM keys WHERE exp > ?;", (int(datetime.datetime.utcnow().timestamp()),))
    keys = cursor.fetchall()
    connect.close()
    return [key_row[0] for key_row in keys]
    
class MyServer(BaseHTTPRequestHandler):
    """creating a JWKS server via class"""
    def __init__(self, *args, **kwargs):
        fname = "totally_not_my_privateKeys.db"
        create_open_db(fname)
        expiration1 = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
        store_private_key(fname, pem, expiration1)
        expiration2 = int((datetime.datetime.utcnow() + datetime.timedelta(seconds=0)).timestamp())
        store_private_key(fname, expired_pem, expiration2)
        super().__init__(*args, **kwargs) 
    
    #used chatgpt to find out what send_response means
    #used prompt "send_response meaning in python"
    def do_put(self):
        """Sends a HTTP code 405 to client"""
        self.send_response(405)
        self.end_headers()
        return

    def do_patch(self):
        """Sends a HTTP code 405 to client"""
        self.send_response(405)
        self.end_headers()
        return

    def do_delete(self):
        """Sends a HTTP code 405 to client"""
        self.send_response(405)
        self.end_headers()
        return

    def do_head(self):
        """Sends a HTTP code 405 to client"""
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        """Posts a path for the user"""
        #sets path
        print("Recieved POST request")
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            print("Handling /auth request")
            headers = {
                "kid": "goodKID"
            }
            expired = 'expired' in params
            pkey_data = get_private_key("totally_not_my_privateKeys.db", expired)
            if pkey_data is None:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Key not found.")
                return
            pkey = serialization.load_pem_private_key(
                pkey_data,
                password=None,
            )
            #sets token for user and its expiration date
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            #checks if pamas aka parsed_path query is expired
            if expired:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            token = jwt.encode(token_payload, pkey, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response_data = json.dumps({"token": token})
            #writes encoded jwt using utf-8 to a file
            self.wfile.write(response_data.encode())
            return
        elif parsed_path.path == "/register":
            print("/register request known")
            c_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(c_length)
            udata = json.loads(post_data.decode("utf-8"))
            password = str(uuid.uuid4())
            ph = PasswordHasher()
            phash = ph.hash(password)
            store_person("totally_not_my_privateKeys.db", udata['username'], udata['email'], phash)
            self.send_response(201)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response_data = json.dumps({"password": password})
            self.wfile.write(response_data.encode())
            return
        self.send_response(405)
        self.end_headers()
        return

    def do_get(self):
        """gets response from client using json and keys"""
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            #Used ChatGPT prompt "How to read all valid (non-expired) keys from DB and create a JWKS response from those keys"
            vkeys = get_valid_keys("totally_not_my_privateKeys.db")
            jwks_keys = []
            for kdata in vkeys:
                pkey = serialization.load_pem_private_key(kdata, password=None)
                numbers = pkey.private_numbers()
                #sets keys information
                jwks_keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                })
            keys = {
                "keys": jwks_keys
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    #creates webserver
    webServer = HTTPServer((HOSTNAME, SERVERPORT), MyServer)
    try:
        #webserver now has an infinite loop and can handle requests
        #used chatgpt to find out what serve_forever() means
        #used prompt "what does serve_forever() mean
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()

#Chat GTP Prompts Used that Aren't Already Noted
#"How to create or open a SQLite DB file at start using python"
#"How to have private keys to DB"
#"How to generate/store at least one key that expires now (or less) and one key that expires in 1 hour (or more)."
#The above with "HINT: SQLite doesn't have very many datatypes it can work with, and "RSA Private Key" definitely isn't one of them. You'll most likely have to serialize the key to a format on save, and deserialize it on read. A string encoding like PKCS1 PEM format would work well in this case."
#"how to add a private key that immediately expires and another that expires in an hour to this code"
#"What does get error  File "/Users/clairebackus/Desktop/main.py", line 175, in <module> store_private_key(FNAME, numbers, expiration) File "/Users/clairebackus/Desktop/main.py", line 67, in store_private_keycursor.execute("""INSERT INTO keys(key, exp) VALUES (?, ?);sqlite3.InterfaceError: Error binding parameter 0 - probably unsupported type."
#"How to read a private key from the DB"
#"If the “expired” query parameter is not present, read a valid (unexpired) key. If the “expired” query parameter is present, read an expired key. Sign a JWT with that private key and return the JWT."
#"how to add Reads all valid (non-expired) private keys from the DB. Creates a JWKS response from those private keys."