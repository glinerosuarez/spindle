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

# 5. Register Microsoft Entra ID Application & Configure EasyAuth (authsettingsV2)
# Register app in tenant
az ad app create --display-name spindle-gateway-auth
# (App ID: 713ed437-7b85-4886-aa06-7f473519b596, Tenant ID: 9ddaaca1-389f-4cb1-a113-081be6cc25fc)

# Add client secret to App Service app settings
az webapp config appsettings set \
  --resource-group spindle-rg \
  --name spindle-gateway \
  --settings MICROSOFT_PROVIDER_AUTHENTICATION_SECRET="<SECRET>"

# Upgrade App Service authentication configuration to v2
az webapp auth config-version upgrade \
  --resource-group spindle-rg \
  --name spindle-gateway

# Configure Microsoft identity provider and authsettingsV2 with path exclusions:
# globalValidation: requireAuthentication=true, unauthenticatedClientAction=RedirectToLoginPage,
# excludedPaths: ["/mcp", "/mcp/*", "/site", "/site/*"], disableWWWAuthenticate=true

# Disable unused default identity providers (Apple, GitHub, Google, Twitter, Facebook, MSA)
# so ONLY Microsoft Entra ID authentication is active:
az rest --method PUT \
  --uri "/subscriptions/464df81d-e069-465c-bb17-432e255ddc7c/resourceGroups/spindle-rg/providers/Microsoft.Web/sites/spindle-gateway/config/authsettingsV2?api-version=2022-03-01" \
  --body @scratch/auth_settings_update.json
# (where auth_settings_update.json sets identityProviders.apple.enabled=false, etc.)

# 6. Deploy Zip Package
az webapp deploy \
  --resource-group spindle-rg \
  --name spindle-gateway \
  --src-path scratch/spindle_deploy.zip \
  --type zip

# 7. Restart App Service to reset ephemeral /tmp state
az webapp restart \
  --resource-group spindle-rg \
  --name spindle-gateway
```

---

## 4. Verification & Testing Evidence

### Live Security & Architecture Probes (Post-A1/A2/A4/A6/A8)

Executed live against `https://spindle-gateway.azurewebsites.net`:

| Probe Target | Request Headers / Payload | Observed Result | Status | Security Guarantee |
| :--- | :--- | :--- | :--- | :--- |
| **Static Site** (`/site/`) | Default GET | `HTTP/1.1 200 OK` | ✅ PASS | Public project landing page accessible without auth. |
| **Dashboard (Browser)** (`/`) | `Accept: text/html, User-Agent: Mozilla/...` | `HTTP/1.1 302 Found` (redirect to `login.microsoftonline.com/...`) | ✅ PASS | Unauthenticated browser visitors redirected to Entra ID login. |
| **Dashboard (Forged Header)** (`/`) | `X-MS-CLIENT-PRINCIPAL-NAME: linero@usc.edu` (no platform session) | `HTTP/1.1 401 Unauthorized` | ✅ PASS | Platform auth intercepts and drops forged headers; `cloud.py` verifies `WEBSITE_AUTH_ENABLED`. |
| **Approval Write (Forged)** (`/approve/1`) | `POST`, `X-MS-CLIENT-PRINCIPAL-NAME: linero@usc.edu` | `HTTP/1.1 401 Unauthorized` | ✅ PASS | Approval cannot be forged from outside without valid authentication. |
| **Remote MCP (No Key)** (`/mcp`) | No Authorization header | `HTTP/1.1 401 Unauthorized` | ✅ PASS | Excluded from Entra login; requires valid per-agent Bearer token. |
| **Remote MCP (Wrong Key)** (`/mcp`) | `Authorization: Bearer invalid-key` | `HTTP/1.1 401 Unauthorized` | ✅ PASS | Constant-time SHA-256 key check rejects invalid tokens. |
| **Remote MCP Fail-Closed** (`/mcp`) | Header read error / unauthenticated in `SPINDLE_REMOTE=1` | Resolves as `__unauthenticated__` (deny-all policy, 0 emails returned) | ✅ PASS | Header extraction failure fails closed to implicit deny-all unknown agent. |
| **Apple Identity Provider** | `az rest --method GET ...` on authsettingsV2 | `identityProviders.apple.enabled: false` (only Entra enabled) | ✅ PASS | Apple auth template disabled; only Microsoft Entra login accepted. |
| **API Docs (Swagger)** (`/docs`) | Default GET | `HTTP/1.1 404 Not Found` | ✅ PASS | Swagger UI disabled (`docs_url=None`). |
| **API Docs (Redoc)** (`/redoc`) | Default GET | `HTTP/1.1 404 Not Found` | ✅ PASS | Redoc disabled (`redoc_url=None`). |
| **OpenAPI Schema** (`/openapi.json`) | Default GET | `HTTP/1.1 404 Not Found` | ✅ PASS | OpenAPI schema disabled (`openapi_url=None`). |
| **Concurrent MCP Agents** (`/mcp/`) | 20 interleaved concurrent calls (`work-agent` vs `strict-agent`) | 100% correct policy returned per call; 0 cross-contamination | ✅ PASS | MCP SDK `Context.headers` resolves agent per call; no global state mutation. |

---

## 5. Measured Impact Benchmark Output (`scripts/demo_metrics.py`)

```
======================================================================
  SPINDLE MEASURED USEFULNESS METRICS (Alex Rivera Inbox)
======================================================================

1. EMAIL ACCESS CONTROL
  Total Inbox Fixtures:            17 emails
  Unprotected Agent Access:        17 / 17 emails exposed (100%)
  Governed Work Agent Access:      7 / 17 emails returned (41.2%)
  Withheld by Policy:              5 emails (Auth & Health denied)
  Quarantined (Injection Attack):  2 emails (e15 hidden-text injection modeled on EchoLeak [CVE-2025-32711] & e17 visible-text override attempt)
  Held for Human Approval:         3 emails (Financial statements & personal plans)

2. DATA EXPOSURE VS REDACTION
  Sensitive Items in Unprotected:  38 unmasked PII tokens exposed to LLM
    - 21 sensitive values (verification code, reset link, account/routing #, DOB, insurance ID, medical records, addresses, phones)
    - 17 sender email addresses
  Sensitive Items in Governed:
    - Search Snippets:             1 PII token masked with deterministic redaction labels
    - Full Email Bodies (read):    4 PII tokens masked with deterministic redaction labels

  Breakdown of Exposed Items in Unprotected Connector:
    - auth_link           : 1
    - bank_account        : 1
    - dob                 : 1
    - email_address       : 17
    - insurance_id        : 1
    - medical_record      : 1
    - medication          : 2
    - otp                 : 2
    - phone               : 3
    - routing_number      : 1
    - street_address      : 3
    - url                 : 2
    - zip                 : 3

  Breakdown of Redacted Items in Governed Agent Snippets:
    - [REDACTED:compensation]: 1

  Breakdown of Redacted Items in Governed Agent Full Bodies (read_email):
    - [REDACTED:compensation]: 2
    - [REDACTED:phone]: 1
    - [REDACTED:street_address]: 1

3. REHEARSAL LEAK VERIFICATION
  Item                         Unprotected     Governed       
  ---------------------------- --------------- ---------------
  Okta OTP (482913)            EXPOSED         SAFE (Withheld)
  Salary Offer ($185,000)      EXPOSED         SAFE (Redacted)
  Mom's Phone (555-0192)       SAFE            SAFE (Approval)
  Mom's Address                SAFE            SAFE (Approval)
  Lab Diagnosis (A1C)          SAFE            SAFE (Withheld)
  Prescription (Metformin)     EXPOSED         SAFE (Withheld)

4. AGENT SANDBOX & BYPASS ENFORCEMENT
  Shell Execution Attempts:        1 blocked by permission rules
  Direct File Read Attempts:       2 blocked by permission rules
  Direct Data Leaks via Bypass:    0 leaked
  Injection Exfiltration Rate:     0/17 across 3 Grok model tiers (Grok 4.7 Med/Low & 4.5 High)

======================================================================
```

## 6. Security Audit

- Zero hardcoded secrets, private keys, or passwords committed to git.
- Agent Bearer keys in `demo/remote/.cursor/mcp.json` resolve dynamically via `${SPINDLE_AGENT_KEY}` environment variable.
- Server-side keys are stored exclusively as one-way SHA-256 hashes in Azure App Service application settings.
