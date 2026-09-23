import { useEffect, useRef, useState } from "react";
import { startMockStream, stopMockStream } from "../lib/mockData.js";

/**
 * Connects to the Gordian FastAPI event stream at `url`. Falls back to a
 * mock stream when the socket can't be reached so the UI keeps moving in dev.
 *
 * status: "connecting" | "open" | "closed" | "mock"
 */
export function useEventStream(url, { maxBuffer = 500, autoMock = false } = {}) {
  const [events, setEvents] = useState([]);
  const [status, setStatus] = useState("connecting");
  const wsRef = useRef(null);
  const stopMockRef = useRef(null);
  const reconnectRef = useRef(0);

  useEffect(() => {
    let cancelled = false;

    const push = (evt) => {
      if (cancelled) return;
      setEvents((prev) => {
        const next = prev.concat(evt);
        return next.length > maxBuffer ? next.slice(-maxBuffer) : next;
      });
    };

    const fallbackToMock = () => {
      if (!autoMock || cancelled) return;
      setStatus("mock");
      stopMockRef.current = startMockStream(push);
    };

    const connect = () => {
      if (cancelled) return;
      try {
        const ws = new WebSocket(url);
        wsRef.current = ws;
        setStatus("connecting");

        ws.onopen = () => {
          reconnectRef.current = 0;
          setStatus("open");
        };

        ws.onmessage = (msg) => {
          try {
            const data = JSON.parse(msg.data);
            push({ id: `${Date.now()}-${Math.random()}`, ...data });
          } catch {
            push({
              id: `${Date.now()}-${Math.random()}`,
              tool: "raw",
              level: "info",
              msg: String(msg.data),
              ts: new Date().toISOString(),
            });
          }
        };

        ws.onerror = () => {
          ws.close();
        };

        ws.onclose = () => {
          if (cancelled) return;
          setStatus("closed");
          reconnectRef.current += 1;
          if (reconnectRef.current >= 2) {
            fallbackToMock();
            return;
          }
          setTimeout(connect, 1500);
        };
      } catch {
        fallbackToMock();
      }
    };

    if (url) connect();
    else fallbackToMock();

    return () => {
      cancelled = true;
      if (wsRef.current) wsRef.current.close();
      if (stopMockRef.current) stopMockRef.current();
      stopMockStream();
    };
  }, [url, maxBuffer, autoMock]);

  const clear = () => setEvents([]);
  return { events, status, clear };
}
