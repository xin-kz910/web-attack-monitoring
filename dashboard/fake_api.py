from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import random

app = Flask(__name__)
CORS(app)

ATTACK_TYPES = ["SQLI", "XSS", "BRUTE_FORCE", "CMD_INJECTION", "PATH_TRAVERSAL"]
SEVERITY = ["HIGH", "MEDIUM", "LOW"]

FAKE_URLS = [
    "/api/login",
    "/api/search",
    "/admin",
    "/user/profile",
    "/product?id=1",
    "/comment",
]

FAKE_PAYLOADS = [
    "' OR 1=1 --",
    "<script>alert(1)</script>",
    "' UNION SELECT * FROM users --",
    "../../etc/passwd",
    "cat /etc/shadow",
    "' OR '1'='1",
    "<img src=x onerror=alert('XSS')>",
    "../" * 5,
]


def generate_fake_logs(n=30):
    logs = []
    now = datetime.utcnow()

    for i in range(n):
        ts = now - timedelta(minutes=random.randint(0, 300))  # 隨機時間
        t = random.choice(ATTACK_TYPES)
        s = random.choice(SEVERITY)

        logs.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": t,
            "severity": s,
            "ip_address": f"192.168.1.{random.randint(1, 200)}",
            "url": random.choice(FAKE_URLS),
            "payload": random.choice(FAKE_PAYLOADS)
        })

    return logs


@app.route("/logs", methods=["GET"])
def get_logs():
    return jsonify(generate_fake_logs(40))


if __name__ == "__main__":
    print("Fake API running at http://127.0.0.1:5000/logs")
    app.run(host="127.0.0.1", port=5000, debug=True)
