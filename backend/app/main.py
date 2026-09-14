"""
CloudGuard — AI-Powered Cloud Security Monitor
Main FastAPI application entry point.
"""

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.config import settings
from app.database import init_db
from app.routers import dashboard, scans, findings, remediation, settings as settings_router
from app.services.scan_scheduler import set_ws_broadcast, run_scan


# ============================================
# WebSocket Connection Manager
# ============================================

class ConnectionManager:
    """Manages active WebSocket connections for real-time updates."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        print(f"[WS] Client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        print(f"[WS] Client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: str):
        """Broadcast a message to all connected clients."""
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.add(connection)
        # Clean up broken connections
        self.active_connections -= disconnected


manager = ConnectionManager()


# ============================================
# Application Lifecycle
# ============================================

scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    # Startup
    print(f"[*] Starting {settings.app_name} v{settings.app_version}")
    
    # Initialize database
    init_db()
    print("[+] Database initialized")
    
    # Set WebSocket broadcast callback for scan scheduler
    set_ws_broadcast(manager.broadcast)
    
    # Start periodic scan scheduler
    if settings.is_aws_configured:
        scheduler.add_job(
            lambda: asyncio.ensure_future(run_scan("full")),
            "interval",
            minutes=settings.scan_interval_minutes,
            id="periodic_scan",
            replace_existing=True,
        )
        scheduler.start()
        print(f"[+] Periodic scanning enabled (every {settings.scan_interval_minutes} minutes)")
    else:
        print("[!] AWS not configured - periodic scanning disabled")
    
    print(f"[*] CORS origins: {settings.cors_origin_list}")
    print(f"[+] {settings.app_name} is ready!")
    
    yield
    
    # Shutdown
    if scheduler.running:
        scheduler.shutdown()
    print(f"[*] {settings.app_name} shutting down")


# ============================================
# FastAPI Application
# ============================================

app = FastAPI(
    title="CloudGuard API",
    description="AI-Powered Cloud Security Monitor — Detects AWS misconfigurations, analyzes risks with AI, and provides one-click remediation.",
    version=settings.app_version,
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(dashboard.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(remediation.router)
app.include_router(settings_router.router)


# ============================================
# WebSocket Endpoint
# ============================================

@app.websocket("/ws/scan-updates")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time scan updates.
    
    Clients receive messages with types:
    - scan_started: A scan has begun
    - scan_progress: Scan progress update (current scanner, percentage)
    - finding_detected: A new finding was detected in real-time
    - scan_completed: Scan finished with summary
    - scan_failed: Scan encountered an error
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, handle any client messages
            data = await websocket.receive_text()
            # Client can send ping/pong or commands
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ============================================
# Root Endpoint
# ============================================

@app.get("/")
def root():
    """Root endpoint with API information."""
    return {
        "app": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "status": "running",
    }
