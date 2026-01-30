# RevCopilot Project Report

## Overview

RevCopilot is an AI-powered reverse engineering assistant designed to help users analyze binary files (such as CTF crackmes) and extract solutions or insights using a combination of static analysis, symbolic execution, and AI models. The system consists of a Python backend (FastAPI) and a React/Next.js frontend.

---

## Backend (`backend/`)

- **main.py**: The main FastAPI application. It defines API endpoints for uploading binaries, running analysis, polling for results, and health checks. It orchestrates the analysis workflow and manages job status/results.
- **analysis_service.py**: Contains the `AnalysisService` class, which handles the core logic for analyzing binaries. It supports different modes (auto, ai, tutor) and delegates to solvers or AI modules as needed.
- **simple_solver.py**: Implements a hardcoded solver for a specific binary (`medium.bin`). Demonstrates how to reverse a known transformation (XOR, ROL, byte swap) to recover a key.
- **ai_module.py**: Placeholder for AI integration (currently empty). Intended for future expansion to support LLM-based analysis or insights.
- **test_api.py**: Python script to quickly test the backend API endpoints (health check, file upload, result polling) using HTTP requests.
- **final_test.py**: More comprehensive test script that uploads a test binary, polls for results, and prints the solution.
- **requirements.txt**: Lists Python dependencies (angr, claripy, fastapi, uvicorn, etc.).
- **static/index.html**: A simple HTML UI for uploading binaries and viewing results, useful for quick manual testing.

---

## Frontend (`frontend/`)

- **src/app/page.tsx**: Main React page. Handles file upload, mode selection, API calls to the backend, and displays analysis results, hints, and AI insights.
- **src/app/layout.tsx**: Root layout for the Next.js app.
- **src/components/FileUpload.tsx**: React component for drag-and-drop or manual file selection, with validation for binary files.
- **package.json**: Lists frontend dependencies (React, Next.js, TailwindCSS, etc.) and scripts for development/build.
- **next-env.d.ts, tsconfig.json**: TypeScript and Next.js configuration files.

---

## How It Works

1. **User uploads a binary** via the frontend UI.
2. **Frontend sends the file** (and optional API key) to the backend `/api/analyze` endpoint.
3. **Backend processes the file** using the selected mode:
   - **Auto**: Uses symbolic execution (angr) or a hardcoded solver.
   - **AI**: (Planned) Uses an LLM for deeper insights.
   - **Tutor**: (Planned) Provides hints and step-by-step guidance.
4. **Backend returns a job ID**; frontend polls `/api/result/{job_id}` for completion.
5. **Results are displayed** in the frontend, including solutions, transformations, hints, and AI insights.

---

## Example Use Cases

- CTF players wanting to quickly analyze and solve crackme binaries.
- Learners seeking hints or explanations for binary challenges.
- Security researchers automating reverse engineering tasks.

---

## Notes

- For best results, use simple binaries with input checks.
- AI and Tutor modes require a Dartmouth API key (planned/optional).
- The backend can be tested independently using the static HTML UI or test scripts.

---
