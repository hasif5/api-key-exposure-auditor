/*
 * bridge.js — isolated-world end of the private channel to intercept.js.
 *
 * Runs at document_start, before any page script. It picks a random event name
 * and hands it to the MAIN-world interceptor, which then dispatches findings
 * as CustomEvents under that name. A page script can neither listen for a name
 * it does not know nor forge findings under it, which window.postMessage
 * allowed. Findings are buffered here until content.js (document_idle)
 * subscribes.
 *
 * Declared with `var` so content.js, which runs later in the same isolated
 * world, can use `GAKS_BRIDGE` directly.
 */
var GAKS_BRIDGE = (function () {
  var buffer = [];
  var sink = null;
  var ready = false;

  var bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  var channel = 'gaks-';
  for (var i = 0; i < bytes.length; i++) channel += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);

  try {
    document.addEventListener(channel, function (ev) {
      var d;
      try { d = JSON.parse(ev.detail); } catch (e) { return; }
      if (!d || typeof d !== 'object') return;
      if (d.type === '__GAKS_READY__') { ready = true; return; }
      if (sink) sink(d);
      else if (buffer.length < 500) buffer.push(d);
    }, true);

    var announce = function () {
      document.dispatchEvent(new CustomEvent('__gaks_init__', { detail: channel }));
    };

    // If the interceptor is already installed it answers synchronously.
    announce();
    if (!ready) {
      // Otherwise it has not been injected yet: answer its hello once. Both
      // scripts load at document_start, so the offer is withdrawn as soon as
      // that turn ends — a page script must not be able to ask for the name.
      var onHello = function () {
        document.removeEventListener('__gaks_hello__', onHello, true);
        announce();
      };
      document.addEventListener('__gaks_hello__', onHello, true);
      setTimeout(function () { document.removeEventListener('__gaks_hello__', onHello, true); }, 0);
    }
  } catch (e) { /* no document — nothing to bridge */ }

  return {
    // Deliver buffered and future findings to `fn`.
    onFinding: function (fn) {
      sink = fn;
      var q = buffer;
      buffer = [];
      for (var j = 0; j < q.length; j++) { try { fn(q[j]); } catch (e) { /* ignore */ } }
    }
  };
})();
