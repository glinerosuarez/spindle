# Spindle on Microsoft Azure

This document records the exact cloud architecture, resource provisioning commands, authentication configurations, and operational tradeoffs for the Spindle deployment on Microsoft Azure.

---

## 1. Live Deployment Endpoints

| Component | Target URL | Azure Resource | Tier / SKU | Location |
| :--- | :--- | :--- | :--- | :--- |
| **Public Project Site** | `https://victorious-desert-08947171e.5.azurestaticapps.net` | `spindle-site` (Static Web App) | Free | West US 2 |
| **Spindle Dashboard** | `https://spindle-gateway.azurewebsites.net/` | `spindle-gateway` (App Service) | Basic B1 (Linux, Py 3.12) | Central US |
| **Remote Streamable HTTP MCP** | `https://spindle-gateway.azurewebsites.net/mcp/` | `spindle-gateway` (Mounted ASGI app) | Basic B1 (Linux, Py 3.12) | Central US |

---

## 2. Architecture & Design

```
                     ┌────────────────────────────────────────┐
                     │          Microsoft Azure Cloud         │
                     │                                        │
[Gabriel Browser] ───┼─► Entra ID / EasyAuth ──► Dashboard (/)│
                     │   (Restricted to                       │
                     │    linero@usc.edu)                     │
                     │                                        │
[Remote AI Agent] ───┼─► Bearer Auth ──────────► Streamable   │
(Cursor / Claude)    │   (SHA-256 Hash Map in     HTTP MCP    │
                     │    SPINDLE_AGENT_KEYS)     (/mcp)      │
                     │                                 │      │
                     │       Local SSD (/tmp/spindle)  ▼      │
                     │       ┌──────────────────────────────┐ │
                     │       │ • SQLite DB (spindle.db)     │ │
                     │       │ • Active Policy (YAML)       │ │
                     │       │ • Classification Cache       │ │
                     │       └──────────────────────────────┘ │
                     └────────────────────────────────────────┘
```

### Key Architectural Decisions

1. **Unified Single-Process ASGI Gateway (`spindle.cloud:app`)**:
   - The Spindle Dashboard (FastAPI/Jinja2/HTMX) and the Streamable HTTP MCP Server (Starlette ASGI via MCP SDK 2.3.0) run in the **same Python process**.
   - They share the exact same SQLite database and in-memory policy cache, ensuring human approvals in the dashboard instantly unblock remote agent MCP queries without distributed synchronization.

2. **Storage on Local SSD (`SPINDLE_HOME=/tmp/spindle`)**:
   - Azure App Service mounts `/home` over a CIFS/SMB network share. SQLite WAL (Write-Ahead Logging) shared-memory (`.shm`) locking fails and causes database corruption on CIFS mounts.
   - Spindle sets `SPINDLE_HOME=/tmp/spindle`, keeping SQLite entirely on the fast, local non-shared disk.
   - *Tradeoff:* Ephemeral storage resets state on cold restart. On every startup, Spindle automatically copies default policies and warms classification cache for fixture data. For demo and evaluation purposes, this provides predictable, deterministic runs.

3. **LLM Engine Configuration (`LLM_ENABLED=false`)**:
   - The cloud instance runs with `LLM_ENABLED=false`. All data filtering, redaction, and prompt injection detection operate deterministically via Spindle's regex redaction engine and structural heuristic classifiers.
   - Ambiguous emails (e.g. `e16`) classify as `other`, which triggers the human approval gate (`ask`).

4. **Remote MCP Per-Agent Bearer Authentication**:
   - Unlike local stdio MCP (which inherits `SPINDLE_AGENT` from process environment), the remote HTTP endpoint `/mcp` authenticates callers via `Authorization: Bearer <agent-key>`.
   - The gateway computes `hashlib.sha256(key).hexdigest()` and performs constant-time comparison (`hmac.compare_digest`) against `SPINDLE_AGENT_KEYS`.
   - The server resolves the agent identity from the verified key hash (e.g. `work-agent` vs `strict-agent`), preventing agents from impersonating higher-privilege profiles.

5. **Dashboard Access Control**:
   - Restricts dashboard access to Gabriel (`linero@usc.edu`) via Microsoft Entra ID claims (`X-MS-CLIENT-PRINCIPAL-NAME` / `X-MS-CLIENT-PRINCIPAL`).
   - Unauthorized accounts receive `403 Forbidden`.
   - Unauthenticated write actions (e.g. `POST /approve/1`) return `401 Unauthorized`.

---

## 3. Provisioning & Deployment Commands

### Prerequisites
```bash
az login
az account set --subscription "Azure subscription 1"
az provider register --namespace Microsoft.Web
```

### Step 1: Azure Static Web Apps (Free Tier)
```bash
# 1. Create Resource Group
az group create --name spindle-rg --location westus2

# 2. Create Static Web App
az staticwebapp create \
  --name spindle-site \
  --resource-group spindle-rg \
  --location westus2 \
  --sku Free

# 3. Deploy static site
swa deploy ./site --env production --deployment-token "<DEPLOYMENT_TOKEN>"
```

### Step 2 & 3: Azure App Service (Basic B1 Linux)
```bash
# 1. Create App Service Plan (Central US selected for active B1 Linux quota)
az appservice plan create \
  --name spindle-plan \
  --resource-group spindle-rg \
  --location centralus \
  --is-linux \
  --sku B1

# 2. Create Web App with Python 3.12
az webapp create \
  --name spindle-gateway \
  --resource-group spindle-rg \
  --plan spindle-plan \
  --runtime "PYTHON:3.12"

# 3. Configure App Settings
az webapp config appsettings set \
  --resource-group spindle-rg \
  --name spindle-gateway \
  --settings \
    SPINDLE_HOME=/tmp/spindle \
    LLM_ENABLED=false \
    ALLOWED_ENTRA_USERS="linero@usc.edu" \
    SCM_DO_BUILD_DURING_DEPLOYMENT=true \
    SPINDLE_AGENT_KEYS='{"f6b3436f3fb005e1aa405327314be42a8ac3b03a501e463b325dd7852a193112": "work-agent", "0efc74d3b368fa5188525f759e6e5a54d6309ba604b67416b2ac20d2800e8a9d": "strict-agent"}'

# 4. Configure Startup Command
az webapp config set \
  --resource-group spindle-rg \
  --name spindle-gateway \
  --startup-file "/bin/bash startup.sh"

# 5. Deploy Zip Package
az webapp deploy \
  --resource-group spindle-rg \
  --name spindle-gateway \
  --src-path /tmp/spindle_deploy.zip \
  --type zip
```

---

## 4. Verification & Testing Evidence

All tests executed live against `https://spindle-gateway.azurewebsites.net`:

1. **Static Project Page**:
   ```bash
   curl -s -I https://spindle-gateway.azurewebsites.net/site/
   # -> HTTP/1.1 200 OK
   ```

2. **Unauthenticated MCP Protection**:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" https://spindle-gateway.azurewebsites.net/mcp/
   # -> 401
   ```

3. **Wrong Key MCP Protection**:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer invalid-key" https://spindle-gateway.azurewebsites.net/mcp/
   # -> 401
   ```

4. **Unauthenticated Dashboard Approval Block**:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" -X POST https://spindle-gateway.azurewebsites.net/approve/1
   # -> 401
   ```

5. **Unauthorized Entra ID Identity Block**:
   ```bash
   curl -s -i -H "X-MS-CLIENT-PRINCIPAL-NAME: attacker@other.com" https://spindle-gateway.azurewebsites.net/
   # -> HTTP/1.1 403 Forbidden
   ```

6. **Authorized Entra ID Identity Access**:
   ```bash
   curl -s -i -H "X-MS-CLIENT-PRINCIPAL-NAME: linero@usc.edu" https://spindle-gateway.azurewebsites.net/
   # -> HTTP/1.1 200 OK (with spindle_token cookie injected)
   ```

7. **Authenticated Remote MCP Tool Execution**:
   - `initialize` returns standard JSON-RPC capabilities.
   - `tools/list` returns all 5 Spindle tools: `search_email`, `read_email`, `check_approval`, `send_email`, `my_permissions`.
   - `tools/call` for `my_permissions` with `work-agent` Bearer key returns `work-agent` policy (standard, 20 results, 1 custom rule).
   - `tools/call` for `my_permissions` with `strict-agent` Bearer key returns `strict-agent` policy (strict, 5 results, deny by default).
   - `tools/call` for `search_email` generates approval request #1 in hosted dashboard.
   - Approving request #1 via `POST /approve/1` instantly releases the approved emails to `check_approval(1)`.

---

## 5. Security Audit

- Zero hardcoded secrets, private keys, or passwords committed to git.
- Agent Bearer keys in `demo/remote/.cursor/mcp.json` resolve dynamically via `${SPINDLE_AGENT_KEY}` environment variable.
- Server-side keys are stored exclusively as one-way SHA-256 hashes in Azure App Service application settings.
