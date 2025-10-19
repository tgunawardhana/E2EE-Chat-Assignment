import socketio

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8765

sio = socketio.Server(async_mode="eventlet")
app = socketio.WSGIApp(sio)

USER_TO_SID = {}
USER_TO_PUBLIC_PEM = {}

@sio.event
def connect(sid, environ):
    pass

@sio.on("register")
def on_register(sid, data):
    username = data.get("username")
    public_key_pem = data.get("public_key_pem")
    if not username or not public_key_pem:
        sio.emit("error", {"error": "missing username/public_key_pem"}, to=sid)
        return
    USER_TO_SID[username] = sid
    USER_TO_PUBLIC_PEM[username] = public_key_pem
    sio.emit("registered", {"username": username}, to=sid)

@sio.on("get_public_key")
def on_get_public_key(sid, data):
    target_username = data.get("target_username")
    sio.emit("public_key", {
        "target_username": target_username,
        "public_key_pem": USER_TO_PUBLIC_PEM.get(target_username)
    }, to=sid)

@sio.on("key_exchange")
def on_key_exchange(sid, message_obj):
    target_username = message_obj.get("to_username")
    dst = USER_TO_SID.get(target_username)
    if dst:
        sio.emit("key_exchange", message_obj, to=dst)

@sio.on("secure_message")
def on_secure_message(sid, message_obj):
    sender_username = message_obj.get("from_username", "")
    target_username = message_obj.get("to_username", "")
    payload = message_obj.get("payload", {})
    ciphertext_b64 = payload.get("ciphertext_b64", "")
    print(f"[{sender_username}] {ciphertext_b64}")
    dst = USER_TO_SID.get(target_username)
    if dst:
        sio.emit("secure_message", message_obj, to=dst)

if __name__ == "__main__":
    import eventlet
    print(f"[SERVER] tcp://{SERVER_HOST}:{SERVER_PORT}")
    eventlet.wsgi.server(eventlet.listen((SERVER_HOST, SERVER_PORT)), app)
