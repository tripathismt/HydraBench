# HydraBench

HydraBench is a local-first, Docker-sandboxed reliability testing lab for explicitly authorized repositories. It maps API routes from an uploaded ZIP, generates bounded repository-aware cases, runs them in a disposable no-network container, and records analysis plus evidence-based remediation proposals.

## Isolated development environment

HydraBench uses one dedicated Conda environment for Python and Node tooling:

```powershell
conda env create -f environment.yml
conda activate hydrabench
cd frontend
npm install
```

If the environment already exists, update it with `conda env update -f environment.yml --prune`.

## Run the backend

```powershell
conda activate hydrabench
cd backend
uvicorn app.main:app --reload --port 8000
```

## Run the frontend

```powershell
conda activate hydrabench
cd frontend
npm run dev
```

Open `http://localhost:3000`. The API is served on `http://localhost:8000`.

## Current scope and safeguards

- Repository upload/mapping requires an explicit authorization confirmation.
- Node projects with a lockfile and `npm start` script run only in a disposable Docker container with no outbound network, read-only root filesystem, dropped Linux capabilities, memory/CPU/PID limits, and automatic cleanup.
- Generated cases are bounded HTTP checks only; the planner excludes exploit payloads, credential tests, fuzzing, external targets, high-volume traffic, and destructive actions outside disposable-container-safe state.
- Source-aware model planning/remediation is performed only when the run includes model authorization. `.env` files are excluded from source context and Docker build contexts.
- HydraBench reports proposed diffs for human review and does not modify uploaded source automatically.
