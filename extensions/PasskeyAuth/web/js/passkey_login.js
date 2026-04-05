/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Passkey login ceremony for the login page.
 * Uses the Web Authentication API (navigator.credentials.get) to authenticate
 * with a registered passkey and then submits the result to passkey.cgi.
 */
(function () {
  'use strict';

  // Only run if WebAuthn is supported
  if (!window.PublicKeyCredential) return;

  var btn = document.getElementById('passkey-login-btn');
  var errorEl = document.getElementById('passkey-login-error');
  if (!btn) return;

  function showError(msg) {
    errorEl.textContent = msg;
    errorEl.style.display = 'block';
  }

  function hideError() {
    errorEl.style.display = 'none';
  }

  // Base64url helpers
  function base64urlToBuffer(base64url) {
    var base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) base64 += '=';
    var binary = atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function bufferToBase64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function getTargetUri() {
    var params = new URLSearchParams(window.location.search);
    var goTo = params.get('GoTo');
    if (goTo) return goTo;
    var base = BUGZILLA.config.basepath || '/';
    return window.location.origin + base;
  }

  btn.addEventListener('click', async function () {
    hideError();
    btn.disabled = true;
    btn.textContent = 'Waiting for passkey…';

    try {
      // Step 1: Get authentication options from the server
      var beginResp = await fetch(BUGZILLA.config.basepath + 'rest/passkey/login/begin', {
        credentials: 'same-origin'
      });
      if (!beginResp.ok) throw new Error('Failed to start passkey login');
      var beginData = await beginResp.json();

      var options = beginData.options;
      options.challenge = base64urlToBuffer(options.challenge);

      if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(function (c) {
          return {type: c.type, id: base64urlToBuffer(c.id)};
        });
      }

      // Step 2: Call the browser WebAuthn API
      var credential = await navigator.credentials.get({publicKey: options});

      // Step 3: Send the assertion to passkey.cgi
      var body = {
        passkey_token: beginData.passkey_token,
        credentialId: bufferToBase64url(credential.rawId),
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        authenticatorData: bufferToBase64url(credential.response.authenticatorData),
        signature: bufferToBase64url(credential.response.signature),
        target_uri: getTargetUri()
      };

      var completeResp = await fetch(BUGZILLA.config.basepath + 'passkey.cgi', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
      });

      if (!completeResp.ok) {
        var errData = await completeResp.json().catch(function () { return {}; });
        throw new Error(errData.message || 'Passkey authentication failed');
      }

      var result = await completeResp.json();
      if (result.success && result.redirect_to) {
        window.location.href = result.redirect_to;
      } else {
        throw new Error('Unexpected response from server');
      }
    } catch (err) {
      if (err.name === 'NotAllowedError') {
        showError('Passkey authentication was cancelled or timed out.');
      } else if (err.name === 'SecurityError') {
        showError('Passkeys require a secure (HTTPS) connection.');
      } else {
        showError(err.message || 'Passkey authentication failed.');
      }
      btn.disabled = false;
      btn.innerHTML =
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
        '<path d="M15 7a4 4 0 1 0-8 0 4 4 0 0 0 8 0z"/>' +
        '<path d="M5 21v-2a7 7 0 0 1 7-7"/>' +
        '<path d="M17 14l2 2 4-4"/>' +
        '</svg> Sign in with a passkey';
    }
  });
})();
