# AMBROSIA — Global Flood Intelligence Platform

> **Intelligence, mapped at the scale of worlds.**

AMBROSIA is a full-stack, multi-service flood intelligence platform built for hackathon conditions. It fuses satellite SAR (Synthetic Aperture Radar) imagery, predictive LSTM deep learning, road-network graph analysis, and a cinematic React frontend into a cohesive system for global flood detection, risk scoring, and lifeline infrastructure assessment.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Repository Structure](#3-repository-structure)
4. [Subsystem Deep-Dives](#4-subsystem-deep-dives)
   - [4.1 Frontend (React + Vite)](#41-frontend-react--vite)
   - [4.2 API Backend (Vercel Serverless — FastAPI)](#42-api-backend-vercel-serverless--fastapi)
   - [4.3 MongoDB Layer](#43-mongodb-layer)
   - [4.4 Forecasting Model (PyTorch LSTM)](#44-forecasting-model-pytorch-lstm)
   - [4.5 Flood-infra / Lifeline Engine (FastAPI + OSMnx)](#45-flood-infra--lifeline-engine-fastapi--osmnx)
5. [Frontend Pages & Features](#5-frontend-pages--features)
6. [API Reference](#6-api-reference)
7. [Data Flow](#7-data-flow)
8. [Environment Variables](#8-environment-variables)
9. [Local Development Setup (Step-by-Step)](#9-local-development-setup-step-by-step)
10. [Deploying the ML Services (HuggingFace Spaces)](#10-deploying-the-ml-services-huggingface-spaces)
11. [Docker Deployment (Local Testing)](#11-docker-deployment-local-testing)
12. [Vercel Deployment](#12-vercel-deployment)
13. [External Services & APIs](#13-external-services--apis)
14. [Technology Stack Summary](#14-technology-stack-summary)

---

## 1. Project Overview

AMBROSIA addresses a critical real-world problem: **floods are increasing in frequency and severity globally, yet situational awareness — especially for infrastructure planners and emergency responders — remains fragmented and delayed.**

The platform solves this by providing:

| Capability                           | Description                                                                                                                                                                                   |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Live Flood Detection**             | Submit any region on Earth; the backend analyzes NASA/ESA Sentinel-1 SAR change-detection data via Google Earth Engine and returns flood extent, area, depth proxy, and per-patch risk scores |
| **Flash-Flood Forecasting**          | A PyTorch LSTM model trained on a decade of global flood data predicts flash-flood risk from precipitation, soil moisture, temperature, and elevation sequences                               |
| **Risk Dashboard**                   | A separate enhanced-risk API scores and ranks administrative districts within a queried region, returning population, infrastructure, and composite risk classifications                      |
| **Lifeline Infrastructure Analysis** | A road-network graph engine (OSMnx + NetworkX Dijkstra) determines which hospitals and schools remain accessible during a simulated flood scenario                                            |

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        USER BROWSER                                  │
│                                                                      │
│   React + Vite SPA  (Tailwind CSS, Framer Motion, CesiumJS)         │
│   ├── Landing Page   (scroll-animated cinematic narrative)           │
│   ├── Globe Analysis (CesiumJS 3D globe, 3 data views)              │
│   └── Flood Insights (historical runs, SAR imagery, charts, PDF)    │
└───────────────┬──────────────────────────────┬──────────────────────┘
                │  HTTPS                        │  HTTPS
                ▼                               ▼
┌──────────────────────────┐    ┌──────────────────────────────────────┐
│  Vercel Serverless API   │    │   HuggingFace Spaces (Docker)         │
│  /api/* → api/index.py   │    │                                       │
│                          │    │  ┌──────────────────────────────────┐ │
│  FastAPI                 │    │  │  Forecast API (Flash-Flood LSTM) │ │
│  ├── POST /auth/login    │    │  │  POST /forecast                  │ │
│  ├── POST /auth/signup   │    │  └──────────────────────────────────┘ │
│  ├── POST /auth/logout   │    │                                       │
│  ├── GET  /auth/google   │    │  ┌──────────────────────────────────┐ │
│  ├── GET  /auth/google/  │    │  │  Flood Backend (Insights API)    │ │
│  │       callback        │    │  │  POST /analyze                   │ │
│  ├── GET  /auth/me       │    │  │  GET  /runs                      │ │
│  └── POST /auth/         │    │  │  GET  /runs/{id}                 │ │
│         refresh-token    │    │  └──────────────────────────────────┘ │
│                          │    │                                       │
└──────────┬───────────────┘    │  ┌──────────────────────────────────┐ │
           │                    │  │  Enhanced Risk API               │ │
           ▼                    │  │  POST /analyze/risk              │ │
┌──────────────────────────┐    │  └──────────────────────────────────┘ │
│  MongoDB Atlas           │    │                                       │
│  (users collection)      │    │  ┌──────────────────────────────────┐ │
│  ├── email (unique)      │    │  │  Lifeline Engine                 │ │
│  ├── password (bcrypt)   │    │  │  POST /flood-infrastructure      │ │
│  ├── subscription_level  │    │  │  POST /simulate                  │ │
│  ├── auth_provider       │    │  │  GET  /health                    │ │
│  └── created_at          │    │  └──────────────────────────────────┘ │
└──────────────────────────┘    └──────────────────────────────────────┘
                                       │ pulls road network data
                                       ▼
                                OpenStreetMap / Nominatim
```

---

## 3. Repository Structure

```
HackX/
├── .env                          # Root environment variables (secrets)
├── .gitignore
├── .vercelignore
├── vercel.json                   # Vercel deployment config (SPA rewrites + API routing)
│
├── frontend/                     # React + Vite SPA
│   ├── index.html                # App entry HTML
│   ├── package.json              # Dependencies (React 18, CesiumJS, Zustand, Framer Motion…)
│   ├── vite.config.js            # Vite + vite-plugin-cesium config
│   ├── tailwind.config.js        # Tailwind custom palette (ice, low, medium, critical…)
│   ├── .env / .env.example       # Frontend env vars
│   └── src/
│       ├── main.jsx              # React root mount
│       ├── App.jsx               # Root component: routing, auth guard, OAuth callback
│       ├── index.css             # Global stylesheet + Tailwind directives
│       │
│       ├── pages/
│       │   ├── Landing.jsx       # Cinematic scroll-driven landing (240-frame animation)
│       │   ├── GlobeAnalysis.jsx # CesiumJS 3D globe — Detection / Risk / Lifeline views
│       │   ├── FloodInsights.jsx # Historical run explorer, SAR imagery, charts, PDF export
│       │   ├── Login.jsx         # Enterprise split-screen login + Google OAuth
│       │   └── Signup.jsx        # Registration form
│       │
│       ├── components/
│       │   ├── ScrollAnimationViewer.jsx     # Canvas-based frame animation player
│       │   ├── SubscriptionSection.jsx       # Pricing tiers (Free / Pro / Enterprise)
│       │   ├── common/
│       │   │   ├── Nav.jsx                   # Navbar with auth state, tab navigation
│       │   │   ├── LogFeed.jsx               # Live log feed component
│       │   │   ├── RiskBadge.jsx             # Color-coded risk label badge
│       │   │   └── StatCounter.jsx           # Animated number counter
│       │   ├── globe/
│       │   │   ├── CesiumGlobe.jsx           # CesiumJS viewer (5 layered data sources)
│       │   │   ├── RegionForm.jsx            # Country/State/City geocode selector
│       │   │   ├── ResultsPanel.jsx          # Forecast result display
│       │   │   ├── RiskDashboardPanel.jsx    # District-level risk analysis UI
│       │   │   ├── LifelinePanel.jsx         # Infrastructure accessibility analysis UI
│       │   │   ├── ProgressOverlay.jsx       # Animated progress indicator
│       │   │   └── GlobeLegend.jsx           # Globe color legend
│       │   ├── ui/
│       │   │   ├── GeoSearchInput.jsx        # Autocomplete geocode search input
│       │   │   └── CalendarPicker.jsx        # Date range picker
│       │   └── dashboard/
│       │       └── (dashboard components)
│       │
│       ├── stores/               # Zustand global state
│       │   ├── appStore.js       # activeTab, notification, auth token/user
│       │   ├── globeStore.js     # Region selection, detection run state, results
│       │   ├── insightsStore.js  # Historical runs list + selected run detail
│       │   ├── riskStore.js      # Risk dashboard data (district summaries)
│       │   ├── lifelineStore.js  # Lifeline infrastructure data
│       │   ├── mapStore.js       # Map viewport state
│       │   └── apiStore.js       # API playground state + live tester
│       │
│       ├── api/                  # HTTP client modules
│       │   ├── floodDetectApi.js # POST /forecast → HF Forecast API
│       │   ├── geocodeApi.js     # Nominatim search/lookup (with bbox & GeoJSON parsing)
│       │   ├── insightsApi.js    # Insights + Risk + Lifeline API clients
│       │   └── cosmeonApi.js     # Legacy/placeholder API client
│       │
│       ├── hooks/
│       │   ├── useAuth.js        # JWT auth: login, signup, logout, OAuth, token refresh
│       │   ├── useScrollAnimation.js    # Apple-style LERP scroll → frame mapping
│       │   └── useScrollNavigation.js  # Section-level scroll navigation hook
│       │
│       ├── data/
│       │   ├── districts.js      # District metadata + RISK_COLORS map
│       │   ├── endpoints.js      # API playground endpoint definitions
│       │   └── (other static data)
│       │
│       ├── utils/
│       │   └── reports/
│       │       └── generateInsightsReport.js  # jsPDF report generator
│       │
│       └── assets/               # Static images, animation frames
│
├── api/                          # Vercel Serverless FastAPI backend
│   ├── index.py                  # Main FastAPI app (auth endpoints)
│   ├── auth.py                   # JWT creation/verification + Google OAuth config
│   ├── models.py                 # User model (MongoDB CRUD + bcrypt)
│   ├── client.py                 # MongoDB Atlas connection + index creation
│   └── requirements.txt          # fastapi, pymongo, PyJWT, bcrypt, authlib, razorpay…
│
├── mongo/                        # Local/standalone MongoDB FastAPI server
│   ├── app.py                    # FastAPI app factory + router registration
│   ├── run.py                    # Uvicorn entry point
│   ├── routes.py                 # Full auth routes (login, signup, logout, OAuth, refresh)
│   ├── auth.py                   # JWT + Google OAuth helpers (mirrors api/auth.py)
│   ├── models.py                 # User model (mirrors api/models.py)
│   ├── client.py                 # MongoDB connection
│   ├── seed.py                   # Database seeder for test users
│   └── requirements.txt
│
├── Forecasting_Model/            # PyTorch flash-flood LSTM
│   ├── model.py                  # FlashFloodLSTM architecture (LSTM → FC → sigmoid)
│   ├── pipeline.py               # Full training pipeline with ImbalancedFloodDataset
│   ├── dvc.yaml                  # DVC pipeline definition
│   ├── dvc.lock                  # DVC pipeline lock file
│   ├── pyproject.toml
│   ├── requirements.txt          # PyTorch, scikit-learn, pandas, mlflow…
│   ├── requirements-serve.txt    # Serving-only dependencies
│   ├── Dockerfile                # Model serving container
│   ├── .env.example              # MLflow + DagShub + GEE env vars
│   ├── configs/                  # Model hyperparameter configs
│   ├── src/                      # Training source modules
│   │   └── (dataset, trainer, evaluator, feature engineering modules)
│   ├── scripts/                  # Data prep, training, evaluation scripts
│   ├── Docs/                     # Architecture docs
│   └── tests/                    # Model test suite
│
├── Flood-infra/                  # Lifeline Accessibility & Road Network Analysis
│   ├── Dockerfile                # HuggingFace Spaces Docker image
│   ├── README.md                 # Flood-infra specific docs
│   ├── docs/                     # API documentation
│   └── Lifeline_Engine/
│       ├── api.py                # FastAPI REST API (40KB — full endpoint suite)
│       ├── engine.py             # Core graph analysis engine (OSMnx + NetworkX)
│       ├── flood_infrastructure.py  # Infrastructure feature extraction
│       ├── main.py               # Standalone simulation CLI runner
│       ├── utils_geo.py          # Geospatial utilities (UTM projection, node snapping)
│       ├── log_config.py         # Structured logging configuration
│       ├── locustfile.py         # Load testing scenarios
│       ├── test_load.py          # Load test suite
│       ├── requirements.txt      # osmnx, networkx, shapely, geopandas, fastapi…
│       └── requirements-prod.txt # Production-only subset
│
└── docs/                         # Project-level documentation
    └── (architecture diagrams, API specs)
```

---

## 4. Subsystem Deep-Dives

### 4.1 Frontend (React + Vite)

**Stack:** React 18, Vite 7, TailwindCSS 3, Framer Motion 11, Zustand 4, CesiumJS 1.138, Recharts, jsPDF

#### State Management (Zustand stores)

Every store is a singleton created with `zustand`'s `create`. Stores subscribe to each other via `useAppStore` for auth and `useGlobeStore` for detection results.

| Store           | Purpose                                | Key State                                                     |
| --------------- | -------------------------------------- | ------------------------------------------------------------- |
| `appStore`      | Global navigation, notifications, auth | `activeTab`, `notification`, `token`, `user`                  |
| `globeStore`    | Detection run lifecycle                | `country/state/city`, `geocoded`, `status`, `result`, `runId` |
| `insightsStore` | Historical analysis runs               | `runs[]`, `selectedRun`, `fetchRuns()`, `selectRun(id)`       |
| `riskStore`     | Risk dashboard districts               | `districtSummaries[]`, `isLoading`, `error`                   |
| `lifelineStore` | Infrastructure analysis                | `data` (GeoJSON + feature table), `isLoading`                 |
| `mapStore`      | Map viewport                           | viewport bounds                                               |
| `apiStore`      | API playground state                   | `activeEndpoint`, live tester output simulation               |

#### Routing

The app uses **manual SPA routing** — no React Router. `App.jsx` maps a `activeTab` string to a page component and calls `window.history.pushState` to keep the URL in sync. Protected routes (`/globe`, `/insights`) redirect unauthenticated users to `/login`.

```
/ → Landing
/login → Login
/signup → Signup
/globe → GlobeAnalysis  [auth required]
/insights → FloodInsights  [auth required]
```

#### Authentication Hook (`useAuth.js`)

Manages the full auth lifecycle:

- **JWT storage:** `hackx_auth_token` + `hackx_user` in `localStorage`
- **OAuth callback:** On page load, reads `?token=` from URL, decodes the JWT payload client-side, stores data, cleans URL
- **Login/Signup:** `fetch` calls to `VITE_API_URL/auth/login` and `VITE_API_URL/auth/signup`
- **Token refresh:** `POST /auth/refresh-token` with current Bearer token
- **Logout:** `POST /auth/logout` (blacklists token server-side), then clears localStorage

#### Scroll Animation (`useScrollAnimation.js`)

Implements an Apple-style passive scroll animation:

1. Listens to `scroll` events passively (no jank)
2. Uses `requestAnimationFrame` with LERP (linear interpolation) to smoothly track scroll position
3. Maps raw scroll fraction → frame index using a **non-linear keyframe table** (text sections get more scroll runway so the user has time to read)
4. The `LERP` factor is `0.09` (slightly slow for cinematic weight)
5. `ScrollAnimationViewer` renders the correct pre-rendered frame image from the `assets/` folder

---

### 4.2 API Backend (Vercel Serverless — FastAPI)

**Location:** `api/`  
**Entry point:** `api/index.py`  
**Deployment:** Vercel Serverless Functions (via `vercel.json` rewrite: `/api/* → /api/index.py`)

This is a FastAPI app that runs as a single Vercel serverless function. All endpoints are under `/auth/`.

#### Authentication Endpoints

| Method | Path                    | Description                                      |
| ------ | ----------------------- | ------------------------------------------------ |
| `POST` | `/auth/login`           | Email + password login — returns JWT + user      |
| `POST` | `/auth/signup`          | Register new user — returns JWT + user           |
| `POST` | `/auth/logout`          | Blacklists the current JWT                       |
| `GET`  | `/auth/me`              | Returns current user info from JWT               |
| `GET`  | `/auth/google`          | Redirects to Google OAuth consent screen         |
| `GET`  | `/auth/google/callback` | Handles Google OAuth code exchange → returns JWT |
| `POST` | `/auth/refresh-token`   | Issues a fresh JWT for the current user          |
| `GET`  | `/health`               | Health check — `{"status": "ok"}`                |
| `GET`  | `/`                     | Root — returns API name and docs link            |

#### JWT Implementation (`api/auth.py`)

- **Algorithm:** HS256
- **Expiry:** 24 hours
- **Payload fields:** `user_id`, `email`, `subscription_level`, `auth_provider`, `iat`, `exp`
- **Blacklist:** In-memory Python `set()` — resets on function cold-start (use Redis in production)
- **Google OAuth config** loaded from env: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`

#### User Model (`api/models.py`)

MongoDB document structure:

```json
{
  "_id": "ObjectId",
  "email": "user@example.com",
  "password": "$2b$12$...", // bcrypt hash, null for Google users
  "subscription_level": "free | pro | enterprise",
  "auth_provider": "local | google",
  "created_at": "2024-01-01T00:00:00"
}
```

Password hashing uses `bcrypt` with auto-generated salt. Passwords are never returned to the client — `user_to_dict()` strips them.

---

### 4.3 MongoDB Layer

**Location:** `mongo/`  
**Purpose:** Standalone MongoDB FastAPI server for local development (alternative to the Vercel serverless version)

The `mongo/` directory is a full standalone FastAPI server with:

- `app.py` — FastAPI factory with CORS middleware and router registration
- `run.py` — `uvicorn` entry point (defaults to port 5000)
- `routes.py` — All auth routes as an `APIRouter`, including `POST /signup` (not in the Vercel version)
- `seed.py` — Seeds test users into the database

**Connection:** Uses `MONGO_DB_CONNECTION_STRING` env var to connect to MongoDB Atlas (or local MongoDB).

**Indexes created on startup:**

- `email` (unique) on `users` collection

---

### 4.4 Forecasting Model (PyTorch LSTM)

**Location:** `Forecasting_Model/`  
**Purpose:** Train and serve a flash-flood risk prediction model

#### Model Architecture (`FlashFloodLSTM`)

```
Input: [batch_size, sequence_length=24, features=4]
  └── Features: Precipitation_mm, Soil_Moisture, Temperature_C, Elevation_m

LSTM (64 hidden units, 2 layers, dropout=0.2, batch_first=True)
  └── Takes 24-hour sequences

Linear(64 → 32) → ReLU → Dropout(0.2) → Linear(32 → 1)

Output: scalar logit → sigmoid → flood probability [0-1]
```

#### Training Pipeline (`pipeline.py`)

1. **Dataset loading:** `global_flash_flood_data_decade.csv` — a decade of global flash flood records
2. **Sequence extraction:** 24-hour sliding windows
3. **Class imbalance handling:** 10:1 ratio enforcement — for every flood event, keeps up to 10 non-flood sequences (plus `pos_weight=10.0` in `BCEWithLogitsLoss`)
4. **Train/Test split:** 80/20
5. **Optimizer:** Adam, lr=0.001
6. **AMP (Automatic Mixed Precision):** `torch.amp.GradScaler` for CUDA
7. **Checkpointing:** Saves `best_flash_flood_model.pt` whenever test F1 improves
8. **Metrics:** F1-score + ROC-AUC

#### DVC Pipeline (`dvc.yaml`)

The model uses [DVC](https://dvc.org/) for experiment tracking and reproducibility:

- Data versioning via DVC remote (DagShub)
- MLflow tracking URI on DagShub
- GEE (Google Earth Engine) integration for satellite data ingestion

---

### 4.5 Flood-infra / Lifeline Engine (FastAPI + OSMnx)

**Location:** `Flood-infra/Lifeline_Engine/`  
**Deployment:** Docker container on Hugging Face Spaces (port 7860)

This is the most algorithmically complex subsystem.

#### 9-Step Simulation Pipeline (`main.py`)

```
Step 1: Download drive network for target city via OSMnx (OpenStreetMap)
Step 2: Fetch hospitals and schools from OSM (fallback to hardcoded Navi Mumbai set)
Step 3: Build flood polygon — circular buffer at configurable radius/centre
Step 4: Apply flood mask — mark all road edges intersecting the flood zone as `blocked=True`
Step 5: Build crisis subgraph — NetworkX `restricted_view` removes blocked edges (memory-efficient)
Step 6: Snap hub node — find nearest graph node to the hub lat/lon
Step 7: Dual-pass Dijkstra — run baseline (unflooded) and crisis (flooded) shortest paths
Step 8: Generate state table — write `state_table.json` + `state_table.csv`
Step 9: Print human-readable summary with status counts and disruption table
```

#### Facility Classification (`engine.py`)

Each facility is classified into one of three states:

| Status             | Condition                                                     |
| ------------------ | ------------------------------------------------------------- |
| `FULLY_ACCESSIBLE` | Path exists, detour factor < 1.2×                             |
| `LIMITED_ACCESS`   | Path exists but detour factor ≥ 1.2× (20% longer than normal) |
| `CUT_OFF`          | No path exists in the crisis graph                            |

The **detour factor** = `flood_shortest_path_distance / baseline_shortest_path_distance`.

#### Globe Rendering Helpers

`engine.py` also exports functions for CesiumJS visualization:

- `get_path_coords()` — convert node-id path to WGS-84 coordinates (straight-line segments)
- `get_detailed_path_coords()` — follow actual road geometry (reads OSM `geometry` attribute)
- `get_blocked_edge_coords()` — return all blocked road segments as polyline arrays for Cesium `PolylineCollection`
- `get_flood_polygon_coords()` — reproject Shapely flood polygon to WGS-84 ring

#### REST API (`api.py`)

Exposes the engine as a FastAPI service:

| Method | Path                    | Description                                    |
| ------ | ----------------------- | ---------------------------------------------- |
| `GET`  | `/health`               | Health check                                   |
| `POST` | `/simulate`             | Run full simulation for a named place          |
| `POST` | `/flood-infrastructure` | Get GeoJSON infrastructure features for a bbox |
| `GET`  | `/runs`                 | List all simulation runs                       |
| `GET`  | `/runs/{run_id}`        | Get simulation run detail                      |

---

## 5. Frontend Pages & Features

### Landing Page (`/`)

A scroll-driven cinematic experience inspired by Apple product pages:

- **240 animation frames** stored as pre-rendered images in `src/assets/`
- **Non-linear scroll keyframes** control pacing (text sections scroll slower so users can read)
- **6 narrative sections** with Framer Motion entrance/exit animations:
  1. **Hero** — "AMBROSIA" centered (exits fast, 10% scroll runway)
  2. **Doctrine** — Left panel, slides from x:-80 (17% runway)
  3. **Signal Intelligence** — Right panel, slides from x:+80 (17% runway)
  4. **Threat Mapping** — Full-width bottom strip, rises from y:+36 (17% runway)
  5. **Strategic Counsel** — Left panel repeat (17% runway)
  6. **CTA** — Centered, "The world doesn't wait." (22% runway, lingers longest)
- **Below the animation:** `SubscriptionSection` with pricing tiers (Free, Pro, Enterprise) + Razorpay payment integration

### Globe Analysis (`/globe`) — _Auth Required_

Three-view interface built on a full-screen CesiumJS globe:

#### Detection View

1. User selects **Country → State/District → City** via cascading dropdowns (calling Nominatim geocoding)
2. Globe flies to the region with a 2.2s cubic-ease animation
3. Region boundary (GeoJSON Polygon/MultiPolygon) is rendered on the globe with a glowing polyline
4. User picks an **analysis date** and clicks **Submit**
5. Frontend calls `POST /forecast` on the HuggingFace Forecast API
6. **Result** — flood extent, alert level (LOW/MEDIUM/HIGH/CRITICAL), flood area km²
7. Region boundary color updates to match alert level (green/gold/orange/red)

#### Risk View

1. User enters a location/region
2. Calls `POST /analyze/risk` on the Enhanced Risk API
3. Globe renders **concentric circle markers** per district:
   - Outer ring: 15% opacity fill
   - Middle ring: 40% opacity
   - Inner core: 95% solid with district label in JetBrains Mono
   - Radius = `population / 500` (population-scaled)
4. Camera flies isometrically over the entire region

#### Lifeline View

1. Calls `POST /flood-infrastructure` on the Lifeline Engine API
2. Globe renders infrastructure points colored by type:
   - 🔴 Hospitals (RED, 14px)
   - 🔵 Schools (DODGERBLUE, 12px)
   - 🟣 Worship (PURPLE, 12px)
   - 🟢 Residential (LIMEGREEN, 8px)
   - 🟡 Commercial (GOLD, 10px)
   - ⚪ Buildings (GRAY, 4px)
3. Labels fade as you zoom out (NearFarScalar)

### Flood Insights (`/insights`) — _Auth Required_

Historical flood run explorer with full analytics:

- **Run list** — preloaded on auth (fetched once; deduplicated by `insightsStore`)
- **Run rows** — Location, date, severity, risk label, flood area km²; staggered animation (`delay: index * 0.04`)
- **Selecting a run** fetches full detail via `GET /runs/{id}`
- **Detail panel** shows:
  - Stat cards: Flood area, flood %, mean dB drop (SAR signal), processing time
  - Signal Confidence card (High/Medium/Low + reason)
  - Depth proxy card (depth category from SAR backscatter)
  - **SAR Change Detection Image** — actual satellite imagery panel
  - **Patch Table** — per-patch area, centroid lat/lon, risk label
  - **AI Insight Panel** — formatted LLM-generated analysis narrative
  - **Location Trend Chart** — dual-axis Recharts LineChart (flood area km² + flood %)
  - **Date-range re-analysis form** — trigger a new analysis with custom pre/post event windows
- **PDF Export** — `jsPDF` generates a downloadable report from the current run data

### Login & Signup (`/login`, `/signup`)

Enterprise split-screen layout:

- Left panel: Spline 3D interactive model as animated background
- Right panel: Glassmorphism form card
- **"AMBROSIA"** branding top-left
- Options: Email/password or **"Continue with Google"** (initiates OAuth redirect flow)
- Error states displayed inline

---

## 6. API Reference

### Auth API (Vercel Serverless)

Base URL: `https://your-vercel-deployment.vercel.app` (or `http://localhost:5000` locally)

#### `POST /auth/signup`

```json
// Request
{"email": "user@example.com", "password": "mypassword"}

// Response 200
{"token": "eyJ...", "user": {"id": "...", "email": "...", "subscription_level": "free", "auth_provider": "local", "created_at": "..."}}
```

#### `POST /auth/login`

```json
// Request
{"email": "user@example.com", "password": "mypassword"}

// Response 200
{"token": "eyJ...", "user": {...}}

// Response 401
{"detail": "Invalid email or password"}
// OR for Google accounts:
{"detail": "This account uses Google Sign-In"}
```

#### `POST /auth/logout`

```
// Header: Authorization: Bearer <token>
// Response 200: {"message": "Logged out successfully"}
```

#### `GET /auth/me`

```
// Header: Authorization: Bearer <token>
// Response 200: {"user": {"id": "...", "email": "...", ...}}
```

#### `GET /auth/google`

```
// Redirects to Google OAuth consent screen
```

#### `GET /auth/google/callback?code=...`

```
// Exchanges code for Google access token, creates/finds user
// Redirects to: {FRONTEND_URL}?token=<jwt>
```

### Forecast API

Base URL: value of `VITE_FORECAST_API_URL` — see [§10 Deploying the ML Services](#10-deploying-the-ml-services-huggingface-spaces)

#### `POST /forecast`

```json
// Request
{
  "lat": 19.076,
  "lon": 72.877,
  "date": "2024-01-15"
}

// Response 200
{
  "alert_level": "HIGH",
  "flood_area_km2": 124.5,
  "flood_percentage": 18.2,
  "confidence": "Medium"
}
```

### Insights API

Base URL: value of `VITE_INSIGHTS_API_URL`

#### `POST /analyze`

Triggers SAR change detection analysis. Returns run metadata.

#### `GET /runs`

Returns all historical runs: `{"runs": [{...}, ...]}`

#### `GET /runs/{run_id}`

Returns full run detail including SAR imagery URL, patches, AI insight text.

### Lifeline Engine API

Base URL: value of `VITE_LIFELINE_API_URL`

#### `POST /flood-infrastructure`

```json
// Request
{
  "bbox": [72.7, 18.9, 73.1, 19.2],   // [west, south, east, north]
  "flood_radius_m": 500
}

// Response 200
{
  "geojson": {
    "type": "FeatureCollection",
    "features": [
      {
        "type": "Feature",
        "geometry": {"type": "Point", "coordinates": [73.007, 19.033]},
        "properties": {
          "feature_type": "hospital",
          "name": "MGM Hospital Vashi",
          "accessibility_status": "FULLY_ACCESSIBLE",
          ...
        }
      }
    ]
  },
  "summary": {...}
}
```

---

## 7. Data Flow

### Detection Run Flow

```
User selects region (RegionForm)
  → geocodeApi.search() → Nominatim → GeoJSON polygon
  → globeStore.setGeocoded() → CesiumGlobe flies + renders boundary
  → User confirms + picks date
  → floodDetectApi.submitDetection({lat, lon, date})
  → HuggingFace Forecast API
  → globeStore.setResult() → boundary recolors to alert-level color
  → ResultsPanel shows statistics
```

### Insights History Flow

```
useEffect in App.jsx: isAuthenticated → insightsStore.fetchRuns()
  → insightsApi.getRuns() → GET /runs on Flood Backend
  → insightsStore.runs populated (deduped: only fetches once)
  → User navigates to /insights
  → FloodInsights renders RunRow list instantly (no loading delay because preloaded)
  → User clicks RunRow → insightsStore.selectRun(id)
  → insightsApi.getRunDetail(id) → GET /runs/{id}
  → Full detail rendered: stat cards, SAR image, patch table, AI insight, trend chart
```

### OAuth Flow

```
User clicks "Continue with Google"
  → useAuth.loginWithGoogle() → redirect to {API_URL}/auth/google
  → api/index.py redirects to Google consent screen
  → Google redirects to {API_URL}/auth/google/callback?code=...
  → Backend exchanges code for access token → fetches user info → finds/creates user
  → Backend redirects to {FRONTEND_URL}?token=<jwt>
  → App.jsx useEffect detects ?token= URL param → handleOAuthCallback()
  → Decodes JWT payload, stores token + user info → navigates to landing
```

---

## 8. Environment Variables

### Root `.env` (shared by `api/` and `mongo/`)

| Variable                     | Description                                        | Example                                        |
| ---------------------------- | -------------------------------------------------- | ---------------------------------------------- |
| `MONGO_DB_CONNECTION_STRING` | MongoDB Atlas connection string                    | `mongodb+srv://user:pass@cluster.mongodb.net/` |
| `DB_PASS`                    | Database password (used in connection string)      | `your_password`                                |
| `JWT_SECRET`                 | Secret key for JWT signing (change in production!) | `your-very-long-random-secret`                 |
| `GOOGLE_CLIENT_ID`           | Google Cloud OAuth 2.0 Client ID                   | `662868xxxxx.apps.googleusercontent.com`       |
| `GOOGLE_CLIENT_SECRET`       | Google Cloud OAuth 2.0 Client Secret               | `GOCSPX-...`                                   |
| `GOOGLE_REDIRECT_URI`        | OAuth callback URL                                 | `http://localhost:5000/auth/google/callback`   |
| `FRONTEND_URL`               | Used for OAuth redirect after login                | `http://localhost:5173`                        |
| `GCP_PROJECT_ID`             | Google Cloud Platform project ID                   | `hackx-488808`                                 |
| `GROQ_API_KEY`               | Groq LLM API key (for AI insights generation)      | `gsk_...`                                      |
| `DATABASE_URL`               | NeonDB serverless Postgres connection string       | `postgresql://user:pass@host/db`               |
| `CLOUDINARY_CLOUD_NAME`      | Cloudinary CDN cloud name                          | `dqog9d2cs`                                    |
| `CLOUDINARY_API_KEY`         | Cloudinary API key                                 | `148542658886527`                              |
| `CLOUDINARY_API_SECRET`      | Cloudinary API secret                              | `AiMCZ...`                                     |

### Frontend `.env` (`frontend/.env`)

| Variable                | Description                                  | How to get the value                                                                                           |
| ----------------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `VITE_API_URL`          | URL of the auth backend                      | `http://localhost:5000` locally; your Vercel deployment URL in production                                      |
| `VITE_MOCK_MODE`        | Enable mock data mode (skips real API calls) | `false` for real data, `true` for local dev without backends                                                   |
| `VITE_CESIUM_TOKEN`     | Cesium Ion token for satellite imagery       | [ion.cesium.com](https://ion.cesium.com) → Create Account → Tokens; leave blank to use free NaturalEarth tiles |
| `VITE_FORECAST_API_URL` | Flash-flood LSTM forecast API URL            | Your HuggingFace Space URL — see [§10](#10-deploying-the-ml-services-huggingface-spaces)                       |
| `VITE_INSIGHTS_API_URL` | Flood insights / SAR analysis backend URL    | Your HuggingFace Space URL — see [§10](#10-deploying-the-ml-services-huggingface-spaces)                       |
| `VITE_RISK_API_URL`     | Enhanced risk analysis API URL               | Your HuggingFace Space URL — see [§10](#10-deploying-the-ml-services-huggingface-spaces)                       |
| `VITE_LIFELINE_API_URL` | Lifeline engine API URL                      | Your HuggingFace Space URL — see [§10](#10-deploying-the-ml-services-huggingface-spaces)                       |
| `VITE_RAZORPAY_KEY`     | Razorpay API key (for subscription checkout) | [razorpay.com](https://razorpay.com) → API Keys                                                                |
| `VITE_RAZORPAY_ID`      | Razorpay merchant ID                         | Razorpay Dashboard → Account Settings                                                                          |

### Forecasting Model `.env` (`Forecasting_Model/.env`)

| Variable                   | Description                                |
| -------------------------- | ------------------------------------------ |
| `MLFLOW_TRACKING_URI`      | DagShub MLflow tracking endpoint           |
| `MLFLOW_TRACKING_USERNAME` | DagShub username                           |
| `MLFLOW_TRACKING_PASSWORD` | DagShub token                              |
| `AWS_ACCESS_KEY_ID`        | DagShub S3-compatible artifact storage key |
| `AWS_SECRET_ACCESS_KEY`    | DagShub storage secret                     |
| `AWS_DEFAULT_REGION`       | AWS region (`us-east-1`)                   |
| `GEE_PROJECT`              | Google Earth Engine project ID             |

### Lifeline Engine Environment Overrides

Set these before running `main.py` or via Docker `-e` flags:

| Variable           | Default                | Description                               |
| ------------------ | ---------------------- | ----------------------------------------- |
| `LIFELINE_PLACE`   | `"Navi Mumbai, India"` | Target city for road network download     |
| `LIFELINE_FLOOD_R` | `500`                  | Flood zone radius in metres               |
| `LIFELINE_HUB_LAT` | `19.0330`              | Hub point latitude                        |
| `LIFELINE_HUB_LON` | `73.0297`              | Hub point longitude                       |
| `PORT`             | `7860`                 | FastAPI server port (HuggingFace default) |

---

## 9. Local Development Setup (Step-by-Step)

### Prerequisites

- **Node.js** ≥ 18 (for frontend)
- **Python** ≥ 3.11 (for all backend services)
- **MongoDB Atlas account** (or local MongoDB ≥ 6)
- **Git**

---

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourgithub/HackX.git
cd HackX
```

---

### Step 2: Set Up Environment Variables

Copy and fill in the root environment file:

```bash
cp .env .env.local
# Edit .env.local and fill in your actual credentials
```

Copy the frontend environment file:

```bash
cp frontend/.env.example frontend/.env
# Edit frontend/.env — at minimum set VITE_API_URL=http://localhost:5000
```

**Required minimum variables to run locally:**

```dotenv
# Root .env
MONGO_DB_CONNECTION_STRING=mongodb+srv://USER:PASS@cluster.mongodb.net/?appName=Cluster0
JWT_SECRET=a-very-long-random-secret-string-at-least-32-chars
FRONTEND_URL=http://localhost:5173

# frontend/.env
VITE_API_URL=http://localhost:5000
VITE_MOCK_MODE=false
```

For Google OAuth (optional for local dev):

```dotenv
GOOGLE_CLIENT_ID=your_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_client_secret
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback
```

---

### Step 3: Start the Backend (MongoDB Auth Server)

```bash
# Create and activate a Python virtual environment
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate

# Install backend dependencies
pip install -r mongo/requirements.txt

# Load environment variables and start the server
export $(cat .env | grep -v '^#' | xargs)   # Linux/Mac
# Windows PowerShell: Get-Content .env | ForEach-Object { ... }

cd mongo
python run.py
# Server starts at http://localhost:5000
```

You should see:

```
INFO:     Uvicorn running on http://0.0.0.0:5000
INFO:     Started server process
```

**Seed test users (optional):**

```bash
python seed.py
```

---

### Step 4: Start the Frontend

In a new terminal:

```bash
cd frontend
npm install
npm run dev
```

You should see:

```
  VITE v7.x.x  ready in 800ms
  ➜  Local:   http://localhost:5173/
```

Open `http://localhost:5173` in your browser.

---

### Step 5: Verify the Setup

1. Navigate to **http://localhost:5173** — you should see the cinematic landing page
2. Scroll down through all 6 sections
3. Click **"Request Access"** at the bottom → routed to Login page
4. Register a new account or log in
5. Navigate to **Globe Analysis** (`/globe`)
6. Search for a city (e.g., "Mumbai, India"), confirm the region
7. Select a date and click **Submit Analysis**

> **Note:** The flood detection, risk, and lifeline APIs are hosted on HuggingFace Spaces. They may have a **cold-start delay of 30–60 seconds** if they haven't been accessed recently. If you see a timeout, wait and retry.

---

### Step 6: Accessing the API Docs

While the backend is running locally:

- **Interactive API docs (Swagger UI):** http://localhost:5000/docs
- **Alternative API docs (ReDoc):** http://localhost:5000/redoc

---

## 10. Deploying the ML Services (HuggingFace Spaces)

The four ML backend APIs each run as a separate [HuggingFace Space](https://huggingface.co/spaces) using the Docker SDK. After creating a Space, you copy its URL into `frontend/.env`.

### How to Read the Space URL

Every HuggingFace Space has a URL in the format:

```
https://<hf-username>-<space-name>.hf.space
```

That full URL is what goes into the corresponding `VITE_*` env variable.

---

### Space 1 — Lifeline Engine (`VITE_LIFELINE_API_URL`)

The source code is in `Flood-infra/`.

**Step 1:** Create a new Space at [huggingface.co/new-space](https://huggingface.co/new-space)

- SDK: **Docker**
- Suggested name: `lifeline-engine`

**Step 2:** Push the `Flood-infra/` folder as the Space repo:

```bash
# Clone the empty HuggingFace Space repo
git clone https://huggingface.co/spaces/YOUR_HF_USERNAME/lifeline-engine
cd lifeline-engine

# Copy the Flood-infra contents into it
cp -r /path/to/HackX/Flood-infra/. .

# Commit and push
git add .
git commit -m "initial deploy"
git push
```

**Step 3:** Wait for the build to complete (~3–5 min). The Space will show **Running** status.

**Step 4:** Copy the Space URL and add it to `frontend/.env`:

```dotenv
VITE_LIFELINE_API_URL=https://YOUR_HF_USERNAME-lifeline-engine.hf.space
```

> **Tip:** The Lifeline Engine needs `LIFELINE_PLACE`, `LIFELINE_FLOOD_R`, `LIFELINE_HUB_LAT`, and `LIFELINE_HUB_LON` at runtime. Set these as Space **Repository Secrets** under Settings → Repository secrets if you want a default simulation region.

---

### Space 2 — Forecast API (`VITE_FORECAST_API_URL`)

The source code is in `Forecasting_Model/`.

**Step 1:** Create a new Space

- SDK: **Docker**
- Suggested name: `forcast` _(spelling matches existing convention)_

**Step 2:** Push the `Forecasting_Model/` folder to the Space repo (same git subtree approach as above).

**Step 3:** The `Dockerfile` in `Forecasting_Model/` starts the FastAPI serving layer. Confirm the build succeeds.

**Step 4:** Add to `frontend/.env`:

```dotenv
VITE_FORECAST_API_URL=https://YOUR_HF_USERNAME-forcast.hf.space
```

---

### Space 3 — Flood Insights Backend (`VITE_INSIGHTS_API_URL`)

This is the SAR change-detection backend (not included in this repo's source — it is a separate service). Deploy it independently in a HuggingFace Space (or any hosting platform that gives you an HTTPS URL).

```dotenv
VITE_INSIGHTS_API_URL=https://YOUR_HF_USERNAME-hackx-flood-backend.hf.space
```

The API must expose:

| Method | Path             | Description                                      |
| ------ | ---------------- | ------------------------------------------------ |
| `POST` | `/analyze`       | Trigger SAR analysis for a location + date range |
| `GET`  | `/runs`          | List all historical runs                         |
| `GET`  | `/runs/{run_id}` | Get full detail for a single run                 |

---

### Space 4 — Enhanced Risk API (`VITE_RISK_API_URL`)

A separate service that returns district-level risk scores for a given region. Deploy as a HuggingFace Space or HTTPS service.

```dotenv
VITE_RISK_API_URL=https://YOUR_HF_USERNAME-enhanced-risk-api.hf.space
```

The API must expose:

| Method | Path            | Description                                                                            |
| ------ | --------------- | -------------------------------------------------------------------------------------- |
| `POST` | `/analyze/risk` | Returns a list of `districtSummaries` with `bbox`, `population`, `risk_classification` |

---

### Setting the Final `.env`

After all four Spaces are running, your `frontend/.env` should look like:

```dotenv
VITE_API_URL=https://your-project.vercel.app          # or http://localhost:5000 locally
VITE_MOCK_MODE=false
VITE_CESIUM_TOKEN=your_cesium_ion_token_here           # optional

VITE_FORECAST_API_URL=https://YOUR_HF_USERNAME-forcast.hf.space
VITE_INSIGHTS_API_URL=https://YOUR_HF_USERNAME-hackx-flood-backend.hf.space
VITE_RISK_API_URL=https://YOUR_HF_USERNAME-enhanced-risk-api.hf.space
VITE_LIFELINE_API_URL=https://YOUR_HF_USERNAME-lifeline-engine.hf.space
```

> ⚠️ **Never commit `frontend/.env` to Git.** It is listed in `.gitignore`. Use `frontend/.env.example` as the template — it contains only placeholder values.

---

## 11. Docker Deployment (Local Testing)

### Lifeline Engine

The Lifeline Engine is packaged as a Docker container for HuggingFace Spaces:

```bash
cd Flood-infra

# Build the image
docker build -t lifeline-engine .

# Run locally (maps HF default port 7860 to host 7860)
docker run -p 7860:7860 \
  -e LIFELINE_PLACE="Mumbai, India" \
  -e LIFELINE_FLOOD_R=1000 \
  -e LIFELINE_HUB_LAT=19.0760 \
  -e LIFELINE_HUB_LON=72.8777 \
  lifeline-engine
```

The container:

- Runs as non-root user `appuser` (uid=1000, matching HuggingFace Spaces)
- Sets `XDG_CACHE_HOME=/app/.cache` to redirect OSMnx HTTP cache
- Exposes port 7860
- Health check: `GET /health` every 30s
- Start command: `uvicorn api:app --host 0.0.0.0 --port 7860 --workers 1`

### Forecasting Model

```bash
cd Forecasting_Model

# Build the model serving container
docker build -t flood-forecast .

# Run
docker run -p 7860:7860 flood-forecast
```

---

## 11. Vercel Deployment

The entire project (frontend + auth API) deploys as a single Vercel project:

### Step 1: Install Vercel CLI

```bash
npm install -g vercel
```

### Step 2: Set Environment Variables in Vercel Dashboard

Go to **Project Settings → Environment Variables** and add all variables from the [Environment Variables section](#8-environment-variables). At minimum:

```
MONGO_DB_CONNECTION_STRING  → your Atlas URI
JWT_SECRET                  → long random string
FRONTEND_URL                → https://your-project.vercel.app
GOOGLE_CLIENT_ID            → from Google Cloud Console
GOOGLE_CLIENT_SECRET        → from Google Cloud Console
GOOGLE_REDIRECT_URI         → https://your-project.vercel.app/api/auth/google/callback
```

> ⚠️ **Critical:** Update `GOOGLE_REDIRECT_URI` to use your actual Vercel domain, not localhost.

### Step 3: Deploy

```bash
vercel --prod
```

Or push to the `main` branch if you've connected your GitHub repo to Vercel (auto-deploy enabled).

### How It Works (`vercel.json`)

```json
{
  "buildCommand": "cd frontend && npm install && npm run build",
  "outputDirectory": "frontend/dist",
  "rewrites": [
    { "source": "/api/(.*)", "destination": "/api/index.py" },
    { "source": "/(.*)", "destination": "/index.html" }
  ]
}
```

- All `/api/*` requests → `api/index.py` (FastAPI serverless)
- All other requests → `index.html` (React SPA client-side routing)
- Assets are served with 1-year cache headers (`immutable`)
- Security headers: `X-Content-Type-Options`, `X-Frame-Options: DENY`, `X-XSS-Protection`

---

## 12. Hugging Face Spaces Deployment (Lifeline Engine)

### Step 1: Create a HuggingFace Space

1. Go to [huggingface.co/new-space](https://huggingface.co/new-space)
2. Select **Docker** as the SDK
3. Name it `lifeline-engine`

### Step 2: Push the Docker Context

```bash
cd Flood-infra

# Add HuggingFace remote
git remote add hf https://huggingface.co/spaces/YOUR_USERNAME/lifeline-engine

# Push (only push the Flood-infra folder)
git subtree push --prefix=Flood-infra hf main
```

### Step 3: Configure Space Settings

In the Space settings, set **Port** to `7860` (already in the Dockerfile).

The Space will automatically build and deploy. Monitor build logs in the HuggingFace UI.

---

## 13. External Services & APIs

| Service                       | Purpose                                                     | Configuration                                                          |
| ----------------------------- | ----------------------------------------------------------- | ---------------------------------------------------------------------- |
| **MongoDB Atlas**             | User data storage                                           | `MONGO_DB_CONNECTION_STRING`                                           |
| **Google OAuth 2.0**          | Social login                                                | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`                             |
| **OpenStreetMap / Nominatim** | Geocoding, boundary lookup                                  | No key required (User-Agent: `COSMEON-FloodDetection/1.0`)             |
| **HuggingFace Spaces**        | Hosting ML APIs                                             | Free tier — may cold-start                                             |
| **NASA/ESA Sentinel-1 SAR**   | Satellite imagery (via Google Earth Engine in Insights API) | `GEE_PROJECT`                                                          |
| **Google Earth Engine**       | SAR change detection pipeline                               | `GEE_PROJECT`                                                          |
| **Cesium Ion** (optional)     | Satellite base map for globe                                | `VITE_CESIUM_TOKEN` — falls back to NaturalEarth tiles                 |
| **Groq LLM**                  | AI-generated flood event narratives                         | `GROQ_API_KEY`                                                         |
| **Razorpay**                  | Subscription payment processing                             | `VITE_RAZORPAY_KEY`, `VITE_RAZORPAY_ID`                                |
| **Cloudinary**                | Image CDN (SAR imagery hosting)                             | `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET` |
| **NeonDB** (PostgreSQL)       | Additional serverless database                              | `DATABASE_URL`                                                         |
| **DagShub / DVC**             | ML experiment tracking + model versioning                   | DVC remote config in `Forecasting_Model/`                              |
| **MLflow**                    | Model metric logging                                        | `MLFLOW_TRACKING_URI`                                                  |

---

## 14. Technology Stack Summary

### Frontend

| Technology    | Version            | Role                                              |
| ------------- | ------------------ | ------------------------------------------------- |
| React         | 18.3               | UI framework                                      |
| Vite          | 7.3                | Build tool + dev server                           |
| TailwindCSS   | 3.4                | Utility-first CSS                                 |
| Framer Motion | 11.3               | Animations (page transitions, section animations) |
| CesiumJS      | 1.138              | 3D globe renderer                                 |
| Zustand       | 4.5                | Global state management                           |
| Recharts      | 2.12               | Data visualization (line charts)                  |
| jsPDF         | 4.2                | PDF report generation                             |
| Spline        | `react-spline` 4.1 | Interactive 3D background (login page)            |

### Backend (Auth API)

| Technology    | Version | Role                            |
| ------------- | ------- | ------------------------------- |
| FastAPI       | 0.104   | API framework                   |
| PyJWT         | 2.8     | JWT generation and verification |
| bcrypt        | 4.1     | Password hashing                |
| pymongo       | 4.5     | MongoDB driver                  |
| requests      | 2.31    | Google OAuth token exchange     |
| authlib       | 1.3     | OAuth 2.0 library               |
| python-dotenv | 1.0     | Environment management          |
| razorpay      | 1.4     | Payment processing              |

### Forecasting Model

| Technology   | Role                              |
| ------------ | --------------------------------- |
| PyTorch      | LSTM model training and inference |
| scikit-learn | StandardScaler, F1/AUC metrics    |
| pandas       | Dataset loading and manipulation  |
| DVC          | Model versioning and pipeline     |
| MLflow       | Experiment tracking               |

### Lifeline Engine

| Technology | Role                                                       |
| ---------- | ---------------------------------------------------------- |
| FastAPI    | REST API framework                                         |
| OSMnx      | OpenStreetMap road network download + projection           |
| NetworkX   | Graph algorithms (Dijkstra shortest path, restricted_view) |
| GeoPandas  | Geospatial DataFrames                                      |
| Shapely    | Polygon geometry operations                                |
| pyproj     | Coordinate system projections (UTM ↔ WGS-84)               |
| uvicorn    | ASGI server                                                |
| locust     | Load testing                                               |

---

## Common Issues & Troubleshooting

### Globe won't load / black screen

- Check browser console for Cesium errors
- Ensure `VITE_CESIUM_TOKEN` is set (or leave empty — it falls back to NaturalEarth tiles)
- Cesium requires a modern browser with WebGL support

### Auth API returns 401 on login

- Verify `MONGO_DB_CONNECTION_STRING` includes correct credentials
- Check that `JWT_SECRET` matches between the API and any token issued
- Ensure the MongoDB Atlas cluster allows connections from your IP (Atlas IP Allowlist)

### HuggingFace API timeout / cold start

- Wait 60 seconds and retry — HF Spaces go to sleep after inactivity
- Check https://huggingface.co/spaces/harshilforworks/forcast for Space status

### Google OAuth not working locally

- Ensure `GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback` exactly matches what's registered in Google Cloud Console
- Add `http://localhost:5000` to the **Authorized JavaScript origins** in Google Cloud Console
- Check the backend is running on port 5000

### Nominatim returns no results

- Search strings must be in English
- Very specific local addresses may not resolve — try city/state/country format
- Nominatim rate-limits requests; don't hammer it in rapid succession

### Lifeline Engine takes too long

- Downloading OSM road networks for large cities (e.g., Mumbai) can take 30–120 seconds on first call
- OSMnx caches results to `~/.cache/osmnx` — subsequent calls are instant
- Reduce `LIFELINE_FLOOD_R` for faster computation

---

_Built with ❤️ for HackX — a planetary-scale flood intelligence platform._
