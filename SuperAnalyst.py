import ollama
from flask import Flask, request, jsonify

MODEL = "llama3:8b"

SYSTEM_PROMPT_ANALYZE = (
    "You are a senior SOC / DFIR cybersecurity assistant. "
    "Analyze command-line, PowerShell, and shell commands for security risks. "
    "Respond short, raw text only."
)

SYSTEM_PROMPT_CASE = (
    "You are a senior SOC analyst. You will produce a formal SOC case summary. "
    "Format MUST follow:\n"
    "Severity: (Low/Medium/High/Critical)\n"
    "Confidence: (0-100%)\n"
    "Reason:\n"
    "- List the concrete signals: VT score, AbuseIPDB, GreyNoise, decoded payload, behavior.\n"
    "Actions:\n"
    "- Bullet list of recommended actions.\n"
    "Evidence Summary:\n"
    "- VERY short bullet summary.\n"
    "Do NOT use markdown or bold. Only raw text."
)

app = Flask(__name__)


@app.route("/", methods=["GET"])
def health():
    return "SuperAnalyst API is running", 200


@app.route("/generate", methods=["POST"])
def generate():
    try:
        body = request.get_json(force=True)
        cmd = (body.get("command") or "").strip()
        if not cmd:
            return jsonify({"error": "Missing command"}), 400

        resp = ollama.chat(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT_ANALYZE},
                {"role": "user", "content": cmd}
            ]
        )

        return jsonify({
            "model": MODEL,
            "analysis": resp["message"]["content"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/case", methods=["POST"])
def case():
    try:
        body = request.get_json(force=True)

        summary_input = (
            f"IOC intel: {body.get('ioc','')}\n"
            f"IOC type: {body.get('ioc_type','')}\n"
            f"VT: {body.get('vt','')}\n"
            f"AbuseIPDB: {body.get('abuse','')}\n"
            f"GreyNoise: {body.get('grey','')}\n"
            f"Decoded: {body.get('decoded','')}\n"
            f"Command: {body.get('command','')}\n"
            f"Asset: {body.get('asset','')}\n"
            f"User: {body.get('user','')}\n"
            f"Time: {body.get('timestamp','')}\n"
        )

        resp = ollama.chat(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT_CASE},
                {"role": "user", "content": summary_input}
            ]
        )

        return jsonify({
            "model": MODEL,
            "case_report": resp["message"]["content"]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=6969, debug=True)