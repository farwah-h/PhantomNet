# PhantomNet++

**A Distributed Framework for Simulating, Detecting, and Defending Against Physical Adversarial Attacks on Vision-Based DNNs**

An industrial collaboration with Nerd Flow (Pvt) Ltd · Final Year Project, BS Cybersecurity, COMSATS University Islamabad

---

## Overview

PhantomNet++ is an enterprise-grade, microservices-based security platform that moves beyond simple adversarial-example detection into proactive, autonomous cyber-physical defense for AI vision systems. It is built around four pillars:

1. **Proactive Threat Intelligence** — simulates real-world digital and physical adversarial attacks (patches, occlusions, perturbations) to anticipate attacker methodologies.
2. **Resilient Detection** — a three-model ensemble (ResNet-50, YOLOv5, custom Autoencoder) cross-verifies every scan using soft voting, hard voting, and a stacking meta-learner.
3. **Explainable Insights** — Grad-CAM, LIME, and SHAP-style explanations give analysts human-interpretable forensic detail on *why* an image was flagged.
4. **Autonomous Response** — a policy-driven engine isolates threats, switches detection posture, and escalates to human analysts in real time, with every action logged on a tamper-evident audit trail.

The system is containerized as nine independent Docker services coordinated through a secure, encrypted, rate-limited communication layer, with a React/TypeScript dashboard for live monitoring and role-based control.

---

## Architecture

| Module | Description | Port | Stack |
|---|---|---|---|
| **DUI** (Frontend) | React dashboard — RBAC, live threat feed, charts, reports | 80 | React 18, TypeScript, Vite, Tailwind, shadcn/ui, Recharts |
| **IVM** | Threat Detection — three-model adversarial ensemble | 5000 | FastAPI, PyTorch, YOLOv5, SQLite |
| **DAG** | Dynamic Attack Generator — adversarial simulation (FGSM/PGD/patch) | 8001 | FastAPI, PyTorch, Foolbox/ART |
| **XAI** | Explainability Engine — Grad-CAM, LIME, SHAP | 5001 | FastAPI, PyTorch |
| **ARE** | Autonomous Response Engine — policy evaluation & mitigation | 8000 | FastAPI, SQLite |
| **AUTH** | Authentication & RBAC | 8002 | FastAPI, bcrypt, SQLite |
| **LSE / SIEM** | Logging & SIEM Engine | 8003 | FastAPI, Elasticsearch |
| **SRC** | Secure Response & Coordination — encryption, signing, certs, rate limiting | 8006 | FastAPI, cryptography (AES-256-GCM, RSA, HMAC-SHA3) |
| **Report** | PDF/JSON report generation | 8004 | FastAPI, ReportLab |

All inter-module traffic is routed through Nginx and secured via the SRC layer (AES-256-GCM encryption, SHA3-256 integrity hashing, HMAC-signed audit logs, 30-day certificate rotation, and per-module rate limiting).

---

## Key Features

- **Ensemble adversarial detection** combining weighted soft voting, weighted hard voting, and a stacking meta-learner, with CVSS v3.1-aligned severity scoring (Critical / High / Medium / Low).
- **Normal vs. Hardened detection postures**, switchable live from Settings or automatically by ARE policy.
- **MITRE ATLAS-aligned default response policies** (isolation, escalation, model switching, logging) with a custom condition language and syntax validator.
- **Role-based access control** for three roles — `admin`, `security_analyst`, `user` — enforced at both the route and component level.
- **Explainable AI reports** (Grad-CAM heatmaps, LIME superpixel maps, SHAP latent-attribution overlays) exportable as PDF/JSON.
- **Tamper-evident SIEM** with SHA3-256 log hashing and per-entry integrity verification.
- **Secure inter-service coordination** with self-signed X.509 certificates, AES-256-GCM payload encryption, and HMAC-SHA3-256 signed audit logs.
- **Attack simulation lab** for generating FGSM/PGD/patch adversarial examples against ResNet-50 and visually comparing before/after results.

---

## Tech Stack

**Frontend:** React 18, TypeScript, Vite, React Router, Tailwind CSS, shadcn/ui (Radix), Recharts, Lucide Icons  
**Backend:** Python 3.11, FastAPI, Uvicorn, PyTorch, TorchVision, YOLOv5, SQLite, Elasticsearch  
**Security:** bcrypt, AES-256-GCM, RSA-2048 X.509 certificates, HMAC-SHA3-256, SHA3-256  
**Infra:** Docker, Docker Compose, Nginx  

---

## System Requirements

### Hardware

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16 GB |
| Disk | 10 GB free | 20 GB free |
| GPU | — | NVIDIA GPU with CUDA 11+ (significantly speeds up IVM and DAG inference) |

> The system runs on CPU only if no GPU is available. Expect slower inference times for the IVM ensemble and DAG attack generation without a CUDA-capable GPU.

### Software — All Deployment Modes

| Dependency | Version | Purpose |
|---|---|---|
| Git | Any recent | Clone the repository |
| Docker | 24+ | Container runtime |
| Docker Compose | 2.20+ | Multi-service orchestration |

### Software — Manual / Development Mode Only

| Dependency | Version | Notes |
|---|---|---|
| Python | 3.11 | Required for all backend services. 3.10 also works. |
| pip | 23+ | Python package installer |
| Node.js | 20 LTS | Required to run the Vite dev server |
| npm | 9+ | Bundled with Node.js |
| CUDA Toolkit | 11.8 or 12.x | Optional — GPU acceleration for PyTorch |
| YOLOv5 repo | Any recent | Must be cloned inside `backend/yolov5/`. See below. |

### Elasticsearch (Required for SIEM / LSE Module)

The SIEM backend (`siem_backend.py`) depends on a running **Elasticsearch 8.x** instance. Without it, the SIEM Logs page will show **OFFLINE** and no security events will be stored or queryable. All other modules continue to function normally.

#### Install Elasticsearch

**Option 1 — Official installer (Windows/macOS/Linux)**

Download from: https://www.elastic.co/downloads/elasticsearch

After installing, start it:

```bash
# Linux / macOS
./bin/elasticsearch

# Windows
.\bin\elasticsearch.bat
```

**Option 2 — Docker (quickest)**

```bash
docker run -d \
  --name elasticsearch \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  elasticsearch:8.13.0
```

**Option 3 — Docker Compose add-on**

Add this service to `docker-compose.yml` before starting the stack:

```yaml
elasticsearch:
  image: elasticsearch:8.13.0
  container_name: phantomnet-es
  environment:
    - discovery.type=single-node
    - xpack.security.enabled=false
  ports:
    - "9200:9200"
  volumes:
    - es_data:/usr/share/elasticsearch/data
```

And add `es_data:` under the `volumes:` key at the bottom.

#### Verify Elasticsearch is running

```bash
curl http://localhost:9200
```

You should see a JSON response with `"tagline" : "You Know, for Search"`. If you see a connection refused error, Elasticsearch is not running — the SIEM module will fall back to offline mode.

#### Configure the SIEM backend

The SIEM backend reads the Elasticsearch host from the environment variable `ES_HOST`. The default is `http://localhost:9200`.

For Docker Compose deployments where Elasticsearch runs in a container named `elasticsearch`:

```bash
# In docker-compose.yml under the siem service:
environment:
  - ES_HOST=http://elasticsearch:9200

# Or for Elasticsearch running on the host machine from inside Docker:
environment:
  - ES_HOST=http://host.docker.internal:9200
```

For manual runs:

```bash
export ES_HOST=http://localhost:9200
python siem_backend.py
```

> **Note:** The SIEM backend automatically creates the `phantomnet-siem` index with the correct field mappings on first startup. You do not need to configure any Elasticsearch index manually.

#### What happens if Elasticsearch is not available

- The **SIEM Logs** page shows "SIEM Backend Offline".
- Log events from all other modules are still emitted (fire-and-forget via `siem_logger.py`) but are silently dropped — no crash or chain failure occurs.
- All other modules (IVM, ARE, DAG, XAI, AUTH, SRC, Report) continue to function independently.

---

### Trained Model Files (Required for IVM and XAI)

The IVM and XAI backends require two trained model weight files that are **not included** in the repository due to file size. Place them in the `backend/models/` directory before starting the services.

```
backend/
└── models/
    ├── autoencoder.pth      # Trained ImprovedAutoencoder weights
    └── yolo-trained.pt      # Custom-trained YOLOv5 checkpoint
```

| File | Description | Required by |
|---|---|---|
| `autoencoder.pth` | Custom skip-connection autoencoder (latent_dim=512) trained on clean ImageNet images. Used for reconstruction-error anomaly detection. | IVM, XAI (SHAP) |
| `yolo-trained.pt` | YOLOv5 checkpoint trained to detect adversarial objects and patches. | IVM |

> If these files are missing, the corresponding model will be skipped with a warning at startup. The ensemble will still run using the remaining available models, but detection accuracy will be reduced. ResNet-50 weights are downloaded automatically from PyTorch Hub on first run.

### YOLOv5 Repository (Required for IVM)

The IVM backend uses the YOLOv5 source repository for NMS and model utilities. Clone it into the backend directory:

```bash
cd backend/
git clone https://github.com/ultralytics/yolov5.git
```

The expected path is `backend/yolov5/`. If this directory is missing, YOLOv5 detection will be disabled and a warning will be printed at startup.

---

## Getting Started

### Option 1 — Docker Compose (Recommended)

Make sure Docker and Docker Compose are installed, Elasticsearch is running and accessible, and the model files are in place.

```bash
git clone <repo-url>
cd phantomnet

# Place model files
mkdir -p backend/models
cp /path/to/autoencoder.pth backend/models/
cp /path/to/yolo-trained.pt backend/models/

# Clone YOLOv5
cd backend && git clone https://github.com/ultralytics/yolov5.git && cd ..

# Start all services
docker compose up --build
```

Open the dashboard at **http://localhost**.

> If Elasticsearch is running as a Docker container, ensure it is on the same Docker network or use `host.docker.internal:9200` as the `ES_HOST` value in `docker-compose.yml`.

### Option 2 — Manual / Development

**1. Clone and set up the backend**

```bash
git clone <repo-url>
cd phantomnet/backend

# Install Python dependencies
pip install -r requirements.txt --break-system-packages

# Clone YOLOv5
git clone https://github.com/ultralytics/yolov5.git

# Place model weights
mkdir -p models
# copy autoencoder.pth and yolo-trained.pt into models/
```

**2. Start Elasticsearch** (see the Elasticsearch section above)

**3. Start each backend service** (each in its own terminal)

```bash
# Recommended startup order — SIEM and SRC first so other services can log from the start
python siem_backend.py          # Port 8003  — start first
python src_backend.py           # Port 8006
python auth_backend.py          # Port 8002
python are-backend.py           # Port 8000
python threat_detection_backend.py  # Port 5000  — loads ML models, takes 20–60s
python xai_backend.py           # Port 5001
python main.py                  # Port 8001 (DAG)
python report_backend.py        # Port 8004
```

**4. Start the frontend**

```bash
cd phantomnet/   # project root
npm install
npm run dev
```

The dashboard is available at **http://localhost:5173** (Vite dev server).

**5. Verify all services are online**

Navigate to **Settings → Module Health** in the dashboard to see the live status of every backend. Alternatively hit each health endpoint directly:

```bash
curl http://localhost:5000/api/health      # IVM
curl http://localhost:8000/api/are/health  # ARE
curl http://localhost:5001/api/xai/health  # XAI
curl http://localhost:8003/api/siem/health # SIEM
curl http://localhost:8006/api/src/health  # SRC
curl http://localhost:8002/api/auth/health # AUTH
curl http://localhost:8004/api/report/health # Report
```

---

## Environment Variables

| Variable | Default | Service | Description |
|---|---|---|---|
| `ES_HOST` | `http://localhost:9200` | SIEM | Elasticsearch base URL |
| `SIEM_URL` | `http://localhost:8003/api/siem/log` | All backends | SIEM ingest endpoint (used by `siem_logger.py`) |
| `SRC_URL` | `http://localhost:8006/api/src/send` | All backends | SRC secure channel endpoint (used by `src_client.py`) |

In Docker Compose these are set per-service in `docker-compose.yml`. For manual runs, export them in your shell before starting each backend, or they fall back to the defaults above.

---

## Default Accounts

| Role | Email | Password |
|---|---|---|
| Administrator | `admin@phantomnet.io` | `admin1234` |
| Security Analyst | `analyst@phantomnet.io` | `analyst1234` |
| Standard User | `user@phantomnet.io` | `user1234` |

> Change these credentials before any non-local deployment. Passwords are bcrypt-hashed and stored in `backend/db/auth.db`.

---

## Role Permissions

| Page | Admin | Security Analyst | Standard User |
|---|:---:|:---:|:---:|
| Dashboard | ✓ | ✓ | ✓ |
| Threat Detection | ✓ | ✓ | ✓ |
| Attack Simulation | ✓ | ✓ | ✗ |
| XAI Engine | ✓ | ✓ | ✓ |
| Response Engine (view) | ✓ | ✓ | ✓ |
| Response Engine (control) | ✗ | ✓ | ✗ |
| Analyst Review (view) | ✓ | ✓ | ✗ |
| Analyst Review (action) | ✗ | ✓ | ✗ |
| SIEM Logs | ✓ | ✓ | ✗ |
| SRC Coordination | ✓ | ✗ | ✗ |
| Settings | ✓ | ✗ | ✗ |

---

## Project Structure

```
.
├── src/                               # React frontend
│   ├── pages/                         # dashboard, threat-detection, attack-simulation,
│   │                                    xai-engine, response-engine, siem-logs,
│   │                                    settings, analyst-review, profile, login
│   ├── components/ui/                 # shadcn/ui primitives
│   └── lib/                           # are-integration.ts, reportUtils.ts, utils.ts
├── backend/
│   ├── models/                        # ← place autoencoder.pth and yolo-trained.pt here
│   ├── yolov5/                        # ← clone ultralytics/yolov5 here
│   ├── uploads/                       # uploaded images (auto-created)
│   ├── db/                            # SQLite databases (auto-created)
│   ├── src_certs/                     # SRC TLS certificates (auto-generated)
│   ├── threat_detection_backend.py    # IVM — ensemble detection
│   ├── main.py                        # DAG — attack simulation
│   ├── xai_backend.py                 # XAI — explainability engine
│   ├── are-backend.py                 # ARE — autonomous response engine
│   ├── auth_backend.py                # AUTH — authentication & RBAC
│   ├── siem_backend.py                # LSE/SIEM — logging engine
│   ├── src_backend.py                 # SRC — secure coordination
│   ├── src_client.py                  # SRC — shared client helper
│   ├── report_backend.py              # Report — PDF/JSON generation
│   ├── database.py                    # IVM SQLite schema & helpers
│   ├── siem_logger.py                 # Shared fire-and-forget SIEM logging helper
│   └── requirements.txt
├── docker/
│   ├── Dockerfile.*                   # Per-service Dockerfiles
│   └── nginx.conf                     # Reverse proxy config
├── docker-compose.yml
└── docs/                              # SDS implementation report (PDF)
```

---

## Security Highlights

- Passwords hashed with **bcrypt**; never stored in plaintext.
- Inter-module messages encrypted with **AES-256-GCM** using a fresh nonce per message.
- Audit log entries signed with **HMAC-SHA3-256**; any tampering is detectable via `GET /api/src/verify/{log_id}`.
- SIEM log entries hashed with **SHA3-256** for independent integrity verification via `GET /api/siem/log/{id}/verify`.
- All module TLS certificates auto-rotate every **30 days** on startup.
- Per-module rate limiting (default 60 req/min, configurable from Settings) protects against denial-of-service between services.

---

## Common Issues

**SIEM shows "Backend Offline"**  
Elasticsearch is not running or not reachable. Check that it is started and verify with `curl http://localhost:9200`. Set `ES_HOST` if it runs on a non-default address.

**IVM starts but YOLOv5 is skipped**  
The `backend/yolov5/` directory is missing. Run `git clone https://github.com/ultralytics/yolov5.git` inside `backend/`.

**Model weights not found warning at startup**  
`autoencoder.pth` or `yolo-trained.pt` are missing from `backend/models/`. The ensemble will run with only the available models. Detection accuracy will be reduced.

**Frontend cannot reach backends**  
When running the Vite dev server (not Docker), all backends must be running locally on their expected ports. Check the Module Health tab in Settings to identify which services are offline.

**ResNet-50 download hangs on first run**  
PyTorch downloads ResNet-50 weights (~100 MB) from the internet on first startup. Ensure the machine has internet access or pre-download using `torch.hub.load` manually.

**GPU not used despite being available**  
Ensure the CUDA toolkit version matches your PyTorch build (`torch.cuda.is_available()` should return `True`). Install the CUDA-enabled PyTorch wheel if needed: https://pytorch.org/get-started/locally/

---

## Testing

The project includes unit, functional, business-rule, and integration test suites covering the DAG attack pipelines, the IVM ensemble decision logic, ARE policy evaluation, XAI explanation generation, SRC encryption/signing, SIEM log integrity, and full end-to-end detection-to-report flows. See the SDS document in `docs/` for the complete test matrix (27 integration tests, 33 unit tests, 26 functional tests, 56 business-rule test cases) and results.

---

## Authors

- Farwah Hamid — FA22-BCT-007
- Munazza Ahmed — FA22-BCT-027

Supervisor: Mrs. Najla Raza · COMSATS University, Islamabad (2022–2026)

---

## License

This project was developed as a Final Year Project in academic collaboration with Nerd Flow (Pvt) Ltd. Licensing terms should be confirmed with the project stakeholders before reuse or redistribution.
