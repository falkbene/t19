from flask import Flask, request, redirect, session, render_template_string
import subprocess
import os
import re
import secrets
import time
import pickle
import random
import string

from flask.sessions import SessionInterface, SessionMixin

import htpasswdlib

PAGE = """
<!doctype html>
<html>
<head>
<title>TUM+!</title>
<style>
body {
    text-align: center;
}

h1 {
    font-family: sans-serif;
    color: #0065bd;
}
#results {
    margin-top: 10px;
    text-align: left;
}
</style>

</head>

<body>
    <h1><span>TUM</span>Blog</h1>
    {% if msg %}
    {{msg|safe}}
    {% else %}
    <h2>Backend login:</h2>
    <form action="/" method="post">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <input type="submit" value="Login">
    </form>
    {% endif %}
</body>
</html>
"""

USERNAMES = [
    "Adrian",
    "Anian",
    "Andreas",
    "Alexander",
    "Carl",
    "Daniel",
    "Dorian",
    "Fabian",
    "Jasper",
    "Lea",
    "Manuel",
    "Nguyet Ha",
    "Julian",
    "Viktor",
    "Yvi"
]

# The following is just code for session storage that prevents cookie replay, otherwise it's not relevant for this task :)
TOKEN = re.compile(r"[0-9a-f]{16}")
SESSION_PATH = "session_store/"
try:
    os.makedirs(SESSION_PATH)
except FileExistsError:
    pass
os.chmod(SESSION_PATH, 0o700)

class Session(dict, SessionMixin):
    def __init__(self, sid):
        self.sid = sid

class FileSessions(SessionInterface):
    def new_session(self):
        sid = secrets.token_hex(16)
        return Session(sid)

    def cleanup_session(self):
        threshold = time.time() - 20*60
        for x in os.scandir(SESSION_PATH):
            s = x.stat()
            if s.st_mtime < threshold:
                os.unlink(x)

    def open_session(self, app, request):
        sid = request.cookies.get("sid")
        if not sid or not TOKEN.match(sid):
            # There is no active session or an invalid one -> create an empty one
            return self.new_session()

        # There is an active session. Restore state from disk
        try:
            with open(SESSION_PATH + "/" + sid, "rb") as f:
                session = pickle.load(f)
            return session
        except FileNotFoundError:
            return self.new_session()
                
    def save_session(self, app, session, response):
        # Save some cpu cycles by garbage collecting old sessions only in about 10 percent
        # of the requests
        if random.random() < 0.1:
            self.cleanup_session()
        if session.modified:
            with open(SESSION_PATH + "/" + session.sid, "wb") as f:
                pickle.dump(session, f)

        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        response.set_cookie("sid", session.sid, httponly=True, domain=domain, path=path, samesite="Strict")


app = Flask(__name__)
app.session_interface = FileSessions()

if not os.path.exists("app-secret.key"):
    with open("app-secret.key", "wb") as f:
        f.write(os.getrandom(32))

with open("app-secret.key", "rb") as f:
    app.secret_key = f.read()

@app.route("/.htpasswd")
def provide_htpasswd():
    if "htpasswd" not in session:
        session["htpasswd"] = generate_htpasswd()

    return session["htpasswd"], 200, {'Content-Type': "text/plain" }

def generate_htpasswd():
    users = random.sample(USERNAMES, 5)

    htpasswd = ""
    for username in users:
        password = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(5))
        print(f"Chosen passwd for {username} is {password}")
        choice = secrets.choice(["bcrypt", "sha1", "md5"])
        print(choice)
        if choice == "bcrypt":
            salt = secrets.token_bytes(16)
            htpasswd += htpasswdlib.bcrypt_hash(username, password, salt)
        elif choice == "md5":
            # Apache generates an 8 character salt via the following procedure..
            n = int((8 * 6 + 7) / 8)
            salt = htpasswdlib.to64(int.from_bytes(secrets.token_bytes(n), byteorder='big'), 8)
            htpasswd += htpasswdlib.md5_hash(username, password, salt)
        elif choice == "sha1":
            htpasswd += htpasswdlib.sha1_hash(username, password)

        htpasswd += "\n"

    return htpasswd

def check_password(username, password):
    for line in session['htpasswd'].split('\n')[:-1]:
        entry = htpasswdlib.parse_htpasswd_line(line)
        if entry.username != username:
            continue

        if entry.alg == "bcrypt":
            bcrypt_hash = htpasswdlib.bcrypt_hash(username, password, entry.salt)
            return bcrypt_hash == line
        elif entry.alg == "md5":
            md5_hash = htpasswdlib.md5_hash(username, password, entry.salt)
            return md5_hash == line
        elif entry.alg == "sha1":
            return htpasswdlib.sha1_hash(username, password) == line
    return False

@app.route("/", methods=["POST", "GET"])
def index():
    if "htpasswd" not in session:
        session["htpasswd"] = generate_htpasswd()
    print("Entering check")
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        print(username,password)

        if check_password(username, password):
            print("FLAGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")
            flag = subprocess.check_output("/bin/flag").decode().strip()
            return render_template_string(PAGE, msg = f"<b>Hi {username}, this is your flag: {flag}</b>")
        else:
            return redirect("/")
    else:
        return render_template_string(PAGE)

