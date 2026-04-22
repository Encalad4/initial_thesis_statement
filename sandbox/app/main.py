# sandbox/app/main.py

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import hashlib
import subprocess
import re

app = FastAPI(title="Sandbox Service")

REPO_BASE = Path("/repos")
REPO_BASE.mkdir(parents=True, exist_ok=True)


class CloneRequest(BaseModel):
    github_url: str


def is_valid_github_url(url: str) -> bool:
    pattern = r"^https://github\.com/[\w\-.]+/[\w\-.]+/?$"
    return re.match(pattern, url) is not None


def make_repo_id(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


@app.get("/")
def root():
    return {"service": "sandbox", "status": "running"}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/clone")
def clone_repo(payload: CloneRequest):
    github_url = payload.github_url.strip()

    if not is_valid_github_url(github_url):
        raise HTTPException(status_code=400, detail="Only public GitHub repository URLs are allowed.")

    repo_id = make_repo_id(github_url)
    target_path = REPO_BASE / repo_id

    if target_path.exists():
        return {
            "success": True,
            "repo_id": repo_id,
            "repo_path": str(target_path),
            "status": "already_cloned"
        }

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", github_url, str(target_path)],
            check=True,
            capture_output=True,
            text=True
        )

        return {
            "success": True,
            "repo_id": repo_id,
            "repo_path": str(target_path),
            "status": "cloned"
        }

    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Git clone failed",
                "stderr": e.stderr
            }
        )