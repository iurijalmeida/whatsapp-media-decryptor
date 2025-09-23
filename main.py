from flask import Flask, request, jsonify
import requests
import base64
from base64 import urlsafe_b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

app = Flask(__name__)

def _b64_urlsafe_decode(s: str) -> bytes:
    # corrige padding
    s = s.replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    return base64.b64decode(s)

@app.route("/decode-media", methods=["POST"])
def decode_media():
    payload = request.get_json(force=True)

    media_url = payload.get("media_url")
    media_key_b64 = payload.get("media_key")
    mimetype = payload.get("mimetype")  # Ex: "image/jpeg"
    auth_token = payload.get("auth_token")  # opcional: Bearer token para baixar o arquivo

    if not media_url or not media_key_b64 or not mimetype:
        return jsonify({"error": "Parâmetros 'media_url', 'media_key' e 'mimetype' são obrigatórios"}), 400

    try:
        # headers opcionais para baixar o arquivo (WhatsApp Cloud API exige Authorization)
        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        resp = requests.get(media_url, headers=headers, timeout=20)
        if resp.status_code != 200:
            return jsonify({
                "error": "Falha ao baixar mídia",
                "http_status": resp.status_code,
                "content_type": resp.headers.get("content-type")
            }), 400

        enc_data = resp.content
        if not enc_data or len(enc_data) <= 10:
            return jsonify({"error": "Arquivo de mídia inválido ou muito curto"}), 400

        # decode media_key (tratar como base64 url-safe)
        try:
            media_key = _b64_urlsafe_decode(media_key_b64)
        except Exception as e:
            return jsonify({"error": "media_key inválido (base64)", "details": str(e)}), 400

        if len(media_key) != 32:
            return jsonify({
                "error": "media_key decodificado não tem 32 bytes (provável chave errada)",
                "media_key_len": len(media_key)
            }), 400

        # tipo de mídia (info string usada no HKDF)
        if mimetype.startswith("image/"):
            info = b"WhatsApp Image Keys"
        elif mimetype.startswith("audio/"):
            info = b"WhatsApp Audio Keys"
        elif mimetype.startswith("video/"):
            info = b"WhatsApp Video Keys"
        elif mimetype.startswith("application/") or mimetype.startswith("text/") or mimetype.startswith("model/"):
            info = b"WhatsApp Document Keys"
        else:
            return jsonify({"error": f"Tipo de mídia não suportado: {mimetype}"}), 400

        # HKDF -> 112 bytes (iv, encKey, macKey, refKey)
        expanded_key = HKDF(master=media_key, key_len=112, salt=None, hashmod=SHA256, num_keys=1, context=info)
        iv = expanded_key[0:16]
        enc_key = expanded_key[16:48]
        # mac_key = expanded_key[48:80]  # se precisar validar MAC
        # ref_key = expanded_key[80:112]

        # remover os últimos 10 bytes (MAC) antes da descriptografia
        ciphertext = enc_data[:-10]

        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)

        # valida e remove padding PKCS7
        try:
            unpadded = unpad(decrypted, AES.block_size)
        except ValueError as e:
            return jsonify({"error": "Padding inválido na descriptografia", "details": str(e)}), 400

        base64_media = base64.b64encode(unpadded).decode("utf-8")
        return jsonify({"success": True, "base64": base64_media})

    except Exception as e:
        return jsonify({"error": "Erro interno", "details": str(e)}), 500

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
