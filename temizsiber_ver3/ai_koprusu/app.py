from flask import Flask, request, jsonify
import requests
import sys

app = Flask(__name__)

LM_STUDIO_URL = "http://host.docker.internal:1234/v1"

@app.route('/status', methods=['GET'])
def durum_kontrolu():

    try:
        res = requests.get(f"{LM_STUDIO_URL}/models", timeout=3)
        if res.status_code == 200:
            return jsonify({"durum": "aktif", "mesaj": "LM Studio bağli ve hazir"}), 200
        return jsonify({"durum": "hata", "mesaj": f"HTTP {res.status_code}"}), 502
    except requests.exceptions.RequestException:
        return jsonify({"durum": "koptu", "mesaj": "Ana makinedeki LM Studio'ya ulasilamiyor"}), 503

@app.route('/ai-sor', methods=['POST'])
def ai_sor():

    if not request.is_json:
        return jsonify({"hata": "Sadece JSON formati kabul edilir"}), 400

    veri = request.json
    gelen_mesaj = veri.get("mesaj", "")
    sys_prompt = veri.get("sys_prompt", "You are a Linux terminal. On the other side, there is an attacker giving you commands. You will generate responses to these commands, and your goal is to be convincing. Pretend that there are files inside a real computer. Pretend that there are hidden files. Generate hidden text when commands like `cat` are executed.")

    max_tokens = veri.get("max_tokens", 1500) 
    temperature = veri.get("temperature", 0.2)

    if not gelen_mesaj.strip():
        return jsonify({"cevap": ""})

    payload = {
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": gelen_mesaj}
        ],
        "temperature": temperature,
        "max_tokens": max_tokens
    }

    try:
        yanit = requests.post(f"{LM_STUDIO_URL}/chat/completions", json=payload, timeout=60)
        yanit.raise_for_status()
        ai_cevabi = yanit.json()["choices"][0]["message"]["content"]
        return jsonify({"cevap": ai_cevabi})
    except Exception as e:

        print(f"[AI KÖPRÜSÜ HATASI]: {str(e)}", file=sys.stderr)
        return jsonify({"hata": "AI Sunucusu yanit vermedi", "detay": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)