type MessageHandler = (message: any) => void;

export class WSService {
  private ws: WebSocket | null = null;
  private messageHandlers: Set<MessageHandler> = new Set();
  private isConnecting = false;
  private reconnectTimer: any = null;

  connect(routingToken: string) {
    if (this.ws?.readyState === WebSocket.OPEN || this.isConnecting) return;
    this.isConnecting = true;

    // Use dynamic WS URL from environment or fallback to localhost
    const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:3000/ws';
    console.log(`Connecting to Relay via WebSocket: ${WS_URL}`);
    
    // Pass routing token as a subprotocol to avoid leaking it in URLs
    this.ws = new WebSocket(WS_URL, [routingToken]);

    this.ws.onopen = () => {
      this.isConnecting = false;
      console.log('WebSocket connected securely to Relay');
      if (this.reconnectTimer) {
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
      }
    };

    this.ws.onmessage = (event) => {
      try {
        let data = event.data;
        try {
          data = JSON.parse(event.data);
        } catch {
          data = event.data;
        }

        // Handle offline queue messages which have a msg_id
        if (data && data.msg_id && data.encrypted_payload) {
            this.messageHandlers.forEach(handler => handler(data.encrypted_payload));
            // Send ACK back to delete from offline queue
            this.ws?.send(JSON.stringify({ type: "ack", msg_id: data.msg_id }));
        } else {
            this.messageHandlers.forEach(handler => handler(data));
        }
      } catch (e) {
        console.error('Failed to handle incoming WS message:', e);
      }
    };

    this.ws.onclose = () => {
      this.isConnecting = false;
      this.ws = null;
      console.log('WebSocket disconnected. Reconnecting in 3s...');
      this.reconnectTimer = setTimeout(() => this.connect(routingToken), 3000);
    };

    this.ws.onerror = (err) => {
      console.error('WebSocket Error:', err);
      this.ws?.close();
    };
  }

  send(sealedEnvelope: any) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(sealedEnvelope));
    } else {
      console.warn('WebSocket not open. Queueing in a real app...');
      // A production app would queue this in IndexedDB and sync on reconnect
    }
  }

  onMessage(handler: MessageHandler) {
    this.messageHandlers.add(handler);
    return () => this.messageHandlers.delete(handler);
  }
}

export const wsService = new WSService();
