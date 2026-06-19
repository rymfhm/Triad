"use client";

import { useEffect, useRef, useCallback } from "react";

const WS_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const WS_URL = WS_BASE.replace(/^http/, "ws") + "/api/ws";

export function useWebSocket(onUpdate: () => void) {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log("[WS] Connected to threat desk");
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "update" || data.type === "pong") {
          onUpdate();
        }
      } catch {
        // ignore non-JSON messages
      }
    };

    ws.onclose = () => {
      console.log("[WS] Disconnected, reconnecting in 5s...");
      reconnectRef.current = setTimeout(connect, 5000);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [onUpdate]);

  useEffect(() => {
    connect();
    const ping = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: "ping" }));
      }
    }, 15000);
    return () => {
      clearInterval(ping);
      clearTimeout(reconnectRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return wsRef;
}
