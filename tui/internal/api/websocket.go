/*
Package api — WebSocket event stream consumer.

Connects to ws://host:port/api/v1/live and pushes parsed events
as Bubble Tea messages via a channel.
*/
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// WSEvent is the parsed JSON from the WebSocket stream.
type WSEvent struct {
	Type      string                 `json:"type"`
	Timestamp string                 `json:"timestamp"`
	Tool      string                 `json:"tool"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Payload   map[string]interface{} `json:"payload"`
	Sequence  int                    `json:"sequence"`
	ScanID    string                 `json:"scan_id"`
}

// BootstrapMessage is the first message from the server on connect.
type BootstrapMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Payload struct {
		Events      []WSEvent `json:"events"`
		EventCount  int       `json:"event_count"`
		ClientCount int       `json:"client_count"`
	} `json:"payload"`
}

// WSClient manages the WebSocket connection lifecycle.
type WSClient struct {
	URL       string
	conn      *websocket.Conn
	Events    chan WSEvent
	Done      chan struct{}
	connected atomic.Bool
	mu        sync.Mutex
	closeOnce sync.Once
}

func NewWSClient(wsURL string) *WSClient {
	return &WSClient{
		URL:    wsURL,
		Events: make(chan WSEvent, 500),
		Done:   make(chan struct{}),
	}
}

// Connect establishes the WebSocket connection and starts reading.
func (ws *WSClient) Connect() error {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	select {
	case <-ws.Done:
		return fmt.Errorf("client closed")
	default:
	}
	if ws.connected.Load() {
		return nil
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, response, err := dialer.Dial(ws.URL, http.Header{"X-Api-Key": []string{os.Getenv("GORDIAN_API_KEY")}})
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return err
	}
	ws.conn = conn
	ws.connected.Store(true)
	conn.SetReadLimit(32 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	// Set up pong handler for keepalive
	ws.conn.SetPongHandler(func(appData string) error {
		_ = ws.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	go ws.readLoop()
	go ws.pingLoop()
	return nil
}

// Close gracefully shuts down the connection.
func (ws *WSClient) Close() {
	ws.closeOnce.Do(func() {
		ws.mu.Lock()
		defer ws.mu.Unlock()
		ws.connected.Store(false)
		if ws.conn != nil {
			_ = ws.conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(time.Second),
			)
			_ = ws.conn.Close()
		}
		close(ws.Done)
	})
}

// IsConnected returns whether the WebSocket is active.
func (ws *WSClient) IsConnected() bool {
	return ws.connected.Load()
}

func (ws *WSClient) pingLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if !ws.connected.Load() {
				return
			}
			if err := ws.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)); err != nil {
				log.Printf("[ws] ping failed: %v", err)
				ws.Close()
				return
			}
		case <-ws.Done:
			return
		}
	}
}

func (ws *WSClient) readLoop() {
	defer ws.Close()

	for {
		_, message, err := ws.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("[ws] unexpected close: %v", err)
			}
			return
		}

		// Try parsing as a regular event first
		var ev WSEvent
		if err := json.Unmarshal(message, &ev); err == nil {
			// Check if it's a bootstrap message
			if ev.Type == "dashboard.bootstrap" {
				var boot BootstrapMessage
				if err := json.Unmarshal(message, &boot); err == nil {
					for _, historicEv := range boot.Payload.Events {
						select {
						case ws.Events <- historicEv:
						default:
							// Channel full, drop oldest
						}
					}
				}
				continue
			}

			select {
			case ws.Events <- ev:
			default:
				// Channel full — drop event to prevent blocking
			}
		}
	}
}

// ConnectWithRetry tries to connect with exponential backoff.
func (ws *WSClient) ConnectWithRetry(maxAttempts int) error {
	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		if err := ws.Connect(); err != nil {
			lastErr = err
			backoff := time.Duration(1<<uint(i)) * 500 * time.Millisecond
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
			time.Sleep(backoff)
			continue
		}
		return nil
	}
	return lastErr
}
