import os
import hmac
import hashlib
import time

from flask import Flask, request, abort
import requests

from jwt_utils import make_jwt

app = Flask(__name__)

GITHUB_APP_ID = os.environ["GITHUB_APP_ID"]
GITHUB_WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"].encode()
GITHUB_INSTALLATION_ID = os.environ["GITHUB_INSTALLATION_ID"]

# Load private key once at startup
with open("private_k.pem", "r", encoding="utf-8") as f:
    PRIVATE_KEY = f.read()


def get_installation_token():
    """Exchange app JWT for an installation access token."""
    jwt_token = make_jwt(GITHUB_APP_ID, PRIVATE_KEY)

    url = f"https://api.github.com/app/installations/{GITHUB_INSTALLATION_ID}/access_tokens"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json",
    }
    resp = requests.post(url, headers=headers, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    return data["token"]


def verify_signature(payload_body: bytes, signature_header: str | None) -> bool:
    """Verify X-Hub-Signature-256 using the webhook secret."""
    if not signature_header:
        return False

    mac = hmac.new(GITHUB_WEBHOOK_SECRET, msg=payload_body, digestmod=hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()
    return hmac.compare_digest(expected, signature_header)


def comment_on_issue(owner: str, repo: str, issue_number: int) -> None:
    """Post a simple comment on the issue using the installation token."""
    token = get_installation_token()
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    body = {
        "body": "Hello from my GitHub App! 🎉"
    }
    resp = requests.post(url, headers=headers, json=body, timeout=10)
    resp.raise_for_status()


@app.post("/webhook")
def webhook():
    payload = request.data
    signature = request.headers.get("X-Hub-Signature-256")

    if not verify_signature(payload, signature):
        abort(401)

    event = request.headers.get("X-GitHub-Event")
    data = request.get_json()

    # React only to newly opened issues
    if event == "issues" and data.get("action") == "opened":
        owner = data["repository"]["owner"]["login"]
        repo = data["repository"]["name"]
        issue_number = data["issue"]["number"]
        comment_on_issue(owner, repo, issue_number)

    return "", 204


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
