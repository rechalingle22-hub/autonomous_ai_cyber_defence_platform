"""WebSocket connection manager for real-time SOC dashboard telemetry streaming."""

import json
from typing import List, Dict, Any
from fastapi import WebSocket


class WebSocketManager:
    """Manages connected client sockets and message broadcasting."""

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcasts a JSON message payload to all active WebSocket clients."""
        payload = json.dumps(message)
        dead_connections: List[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)


ws_manager = WebSocketManager()

