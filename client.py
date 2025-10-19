import argparse, json, base64
from datetime import datetime, timezone
from secrets import token_bytes
from pathlib import Path
import socketio
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding

SERVER_URL = "http://127.0.0.1:8765"
AES_KEY_BYTES = 16
HMAC_KEY_BYTES = 32
CBC_IV_BYTES = 16
SESSION_KEY_TOTAL_BYTES = AES_KEY_BYTES + HMAC_KEY_BYTES
RSA_BITS = 2048

def load_public_key(pem_text):  return serialization.load_pem_public_key(pem_text.encode())
def load_private_key(pem_text): return serialization.load_pem_private_key(pem_text.encode(), password=None)

def public_pem(pub):
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def private_pem(prv):
    return prv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()

def rsa_encrypt_key(public_key, raw_bytes):
    return public_key.encrypt(
        raw_bytes,
        rsa_padding.OAEP(mgf=rsa_padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
    )

def rsa_decrypt_key(private_key, enc_bytes):
    return private_key.decrypt(
        enc_bytes,
        rsa_padding.OAEP(mgf=rsa_padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
    )

def encrypt_message(enc_key_16, mac_key_32, plaintext_str, aad_dict):
    iv = token_bytes(CBC_IV_BYTES)
    padder = sympadding.PKCS7(128).padder()
    padded = padder.update(plaintext_str.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key_16), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    aad_bytes = json.dumps(aad_dict, separators=(",", ":"), sort_keys=True).encode()
    mac = hmac.HMAC(mac_key_32, hashes.SHA256())
    mac.update(aad_bytes + iv + ciphertext)
    mac_bytes = mac.finalize()
    return iv, ciphertext, mac_bytes

def decrypt_message(enc_key_16, mac_key_32, iv, ciphertext, mac_bytes, aad_dict):
    aad_bytes = json.dumps(aad_dict, separators=(",", ":"), sort_keys=True).encode()
    mac = hmac.HMAC(mac_key_32, hashes.SHA256())
    mac.update(aad_bytes + iv + ciphertext)
    mac.verify(mac_bytes)
    decryptor = Cipher(algorithms.AES(enc_key_16), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpad = sympadding.PKCS7(128).unpadder()
    plaintext = unpad.update(padded) + unpad.finalize()
    return plaintext.decode()

def ensure_local_rsa_keys(username):
    prv_path = Path(f"{username}_private.pem")
    pub_path = Path(f"{username}_public.pem")
    if prv_path.exists() and pub_path.exists():
        return load_private_key(prv_path.read_text()), load_public_key(pub_path.read_text())
    prv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    pub = prv.public_key()
    prv_path.write_text(private_pem(prv))
    pub_path.write_text(public_pem(pub))
    return prv, pub

def client_log_path(username): return Path(f"{username}_messages.json")

def append_client_log(username, sender, ciphertext_b64, plaintext_str):
    p = client_log_path(username)
    try:
        existing = json.loads(p.read_text()) if p.exists() else []
    except Exception:
        existing = []
    existing.append({"sender": sender, "ciphertext_b64": ciphertext_b64, "plaintext": plaintext_str})
    p.write_text(json.dumps(existing, indent=2))

def start_chat_session(sio, me, peer, session_key):
    enc_key = session_key[:AES_KEY_BYTES]
    mac_key = session_key[AES_KEY_BYTES: AES_KEY_BYTES + HMAC_KEY_BYTES]
    print(f"{peer} connected to the chat")
    def input_loop():
        while True:
            try:
                plaintext_str = input()
            except EOFError:
                break
            timestamp_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
            aad = {"from": me, "to": peer, "timestamp": timestamp_ms}
            iv, ciphertext, mac_bytes = encrypt_message(enc_key, mac_key, plaintext_str, aad)
            payload = {
                "ciphertext_b64": base64.b64encode(ciphertext).decode(),
                "iv_b64": base64.b64encode(iv).decode(),
                "mac_b64": base64.b64encode(mac_bytes).decode(),
                "timestamp_ms": timestamp_ms
            }
            sio.emit("secure_message", {
                "from_username": me,
                "to_username": peer,
                "payload": payload
            })
            append_client_log(me, me, payload["ciphertext_b64"], plaintext_str)
    sio.start_background_task(input_loop)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True, dest="me")
    parser.add_argument("--peer", dest="peer")
    args = parser.parse_args()
    me = args.me
    peer = args.peer
    session_key = None
    current_peer = peer
    my_private_key, my_public_key = ensure_local_rsa_keys(me)
    sio = socketio.Client()

    @sio.on("registered")
    def on_registered(_):
        if peer:
            sio.emit("get_public_key", {"target_username": peer})

    @sio.on("public_key")
    def on_public_key(data):
        nonlocal session_key
        peer_pub_pem = data.get("public_key_pem")
        if not peer or not peer_pub_pem:
            return
        peer_public_key = load_public_key(peer_pub_pem)
        session_key = token_bytes(SESSION_KEY_TOTAL_BYTES)
        enc_session_key_b64 = base64.b64encode(rsa_encrypt_key(peer_public_key, session_key)).decode()
        sio.emit("key_exchange", {
            "from_username": me,
            "to_username": peer,
            "payload": {
                "enc_session_key_b64": enc_session_key_b64
            }
        })
        start_chat_session(sio, me, peer, session_key)

    @sio.on("key_exchange")
    def on_key_exchange(message_obj):
        nonlocal session_key, current_peer
        if message_obj.get("to_username") != me:
            return
        try:
            enc_session_key_b64 = message_obj["payload"]["enc_session_key_b64"]
            session_key = rsa_decrypt_key(my_private_key, base64.b64decode(enc_session_key_b64.encode()))
            current_peer = message_obj.get("from_username")
            start_chat_session(sio, me, current_peer, session_key)
        except Exception:
            print(f"[{me}] session error")

    @sio.on("secure_message")
    def on_secure_message(message_obj):
        if message_obj.get("to_username") != me:
            return
        payload = message_obj["payload"]
        sender = message_obj.get("from_username")
        ciphertext_b64 = payload["ciphertext_b64"]
        iv_b64 = payload["iv_b64"]
        mac_b64 = payload["mac_b64"]
        timestamp_ms = payload["timestamp_ms"]
        print(f"[{sender}] encrypted: {ciphertext_b64}")
        if not session_key:
            print(f"[{me}] no session")
            return
        try:
            enc_key = session_key[:AES_KEY_BYTES]
            mac_key = session_key[AES_KEY_BYTES: AES_KEY_BYTES + HMAC_KEY_BYTES]
            aad = {"from": sender, "to": message_obj.get("to_username"), "timestamp": timestamp_ms}
            plaintext = decrypt_message(
                enc_key,
                mac_key,
                base64.b64decode(iv_b64.encode()),
                base64.b64decode(ciphertext_b64.encode()),
                base64.b64decode(mac_b64.encode()),
                aad
            )
            print(f"[{sender}] decrypted: {plaintext}")
            append_client_log(me, sender, ciphertext_b64, plaintext)
        except Exception:
            print(f"[{me}] decryption failed")

    sio.connect(SERVER_URL)
    sio.emit("register", {"username": me, "public_key_pem": public_pem(my_public_key)})
    try:
        sio.wait()
    except KeyboardInterrupt:
        pass
    finally:
        sio.disconnect()

if __name__ == "__main__":
    main()
