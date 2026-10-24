from __future__ import annotations

import os
import shutil
from pathlib import Path


def load_dotenv(dotenv_path: Path) -> None:
    if not dotenv_path.exists():
        return
    for line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip("\"'")
        if key not in os.environ:
            os.environ[key] = val


class Config:
    def __init__(self):
        # 1. Load spindle-app/.env if present
        app_dir = Path(__file__).resolve().parent.parent.parent
        load_dotenv(app_dir / ".env")

        # 2. Base directory
        home_str = os.environ.get("SPINDLE_HOME", "~/.spindle")
        self.home = Path(os.path.expanduser(home_str)).resolve()
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)

        # 3. Paths
        self.db_path = self.home / "spindle.db"
        self.policy_path = self.home / "policies.yaml"
        self.log_path = self.home / "spindle.log"
        self.token_path = self.home / "token.json"
        self.credentials_path = self.home / "credentials.json"
        self.incoming_path = self.home / "incoming.json"

        # 4. Copy default policies if missing
        if not self.policy_path.exists():
            default_yaml = app_dir / "policies" / "default.yaml"
            if default_yaml.exists():
                shutil.copyfile(default_yaml, self.policy_path)

        # 5. Runtime settings
        self.agent = os.environ.get("SPINDLE_AGENT", "work-agent")
        self.source = os.environ.get("SPINDLE_SOURCE", "fixtures").lower()
        self.approval_timeout = int(os.environ.get("SPINDLE_APPROVAL_TIMEOUT", "45"))
        self.dashboard_port = int(os.environ.get("SPINDLE_DASHBOARD_PORT", "8765"))

        # 6. LLM config
        self.llm_base_url = os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1")
        self.llm_model = os.environ.get("LLM_MODEL", "muse-spark-1.3" if "meta.ai" in self.llm_base_url else "llama3.2:1b")
        self.llm_api_key = os.environ.get("LLM_API_KEY", "ollama")

        self.llm_timeout = float(os.environ.get("LLM_TIMEOUT", "20"))
        self.llm_enabled = os.environ.get("LLM_ENABLED", "true").lower() in ("true", "1", "yes")

        # Check calhacks/.env fallback for META_DEV_API_KEY if needed
        if (not self.llm_api_key or self.llm_api_key == "ollama") and "meta.ai" in self.llm_base_url:
            calhacks_env = app_dir.parent / "calhacks" / ".env"
            if calhacks_env.exists():
                for line in calhacks_env.read_text().splitlines():
                    if line.startswith("META_DEV_API_KEY="):
                        self.llm_api_key = line.split("=", 1)[1].strip()

        # Claude API
        self.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self.claude_model = os.environ.get("SPINDLE_CLAUDE_MODEL", "claude-opus-5-5")


config = Config()
