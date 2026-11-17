/*
 * cdp.mjs - minimal Chrome DevTools Protocol client (no dependencies).
 *
 * Author: Hasif Ahmed <hasif5@gmail.com> (www.hasif.info)
 *
 * Uses the WebSocket global that ships with Node 22+. Only what the research
 * harness needs: send(), event subscription, and flat-session support.
 */

export class Cdp {
  constructor() {
    this.ws = null;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = [];
  }

  static async connect(wsUrl) {
    const c = new Cdp();
    c.ws = new WebSocket(wsUrl);
    await new Promise((resolve, reject) => {
      c.ws.onopen = resolve;
      c.ws.onerror = (e) => reject(new Error('CDP websocket error: ' + (e && e.message || 'connect failed')));
    });
    c.ws.onmessage = (ev) => c._onMessage(JSON.parse(String(ev.data)));
    return c;
  }

  _onMessage(m) {
    if (m.id) {
      const p = this.pending.get(m.id);
      if (!p) return;
      this.pending.delete(m.id);
      if (m.error) p.reject(new Error(m.error.message + ' (' + p.method + ')'));
      else p.resolve(m.result);
    } else {
      for (const fn of this.listeners) { try { fn(m); } catch (e) { /* listener errors must not kill the socket */ } }
    }
  }

  send(method, params, sessionId) {
    const id = this.nextId++;
    const msg = { id, method, params: params || {} };
    if (sessionId) msg.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, method });
      this.ws.send(JSON.stringify(msg));
    });
  }

  onEvent(fn) { this.listeners.push(fn); }

  close() { try { this.ws.close(); } catch (e) { /* already closed */ } }
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
