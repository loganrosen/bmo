/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Passkey management UI for the user preferences "Passkeys" tab.
 * Handles listing, registering, and deleting passkeys.
 */
(function () {
  'use strict';

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

  function formatDate(dateStr) {
    if (!dateStr) return 'Never';
    var d = new Date(dateStr);
    return d.toLocaleDateString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  }

  var listEl = document.getElementById('passkey-list');
  var registerBtn = document.getElementById('passkey-register-btn');
  var nameInput = document.getElementById('passkey-name');
  var statusEl = document.getElementById('passkey-register-status');

  function showStatus(msg, type) {
    statusEl.className = type === 'error' ? 'passkey-error' : 'passkey-success';
    statusEl.textContent = msg;
    statusEl.style.display = 'block';
  }

  function hideStatus() {
    statusEl.style.display = 'none';
  }

  // Load and render the list of registered passkeys
  async function loadCredentials() {
    try {
      var data = await Bugzilla.API.get('passkey/credentials');
      renderCredentials(data.credentials || []);
    } catch (err) {
      listEl.innerHTML = '<p class="passkey-error">Failed to load passkeys: ' +
        escapeHtml(err.message) + '</p>';
    }
  }

  function escapeHtml(text) {
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  function escapeAttr(text) {
    return escapeHtml(text).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function renderCredentials(credentials) {
    if (!credentials.length) {
      listEl.innerHTML = '<p class="passkey-empty">No passkeys registered yet.</p>';
      return;
    }

    var html = '';
    credentials.forEach(function (cred) {
      html += '<div class="passkey-credential" data-id="' + cred.id + '">' +
        '<div>' +
        '<div class="name">' + escapeHtml(cred.name) + '</div>' +
        '<div class="meta">Registered: ' + formatDate(cred.created_at) +
        ' · Last used: ' + formatDate(cred.last_used_at) + '</div>' +
        '</div>' +
        '<button type="button" class="passkey-delete-btn" data-id="' + cred.id +
        '" data-name="' + escapeAttr(cred.name) + '">Remove</button>' +
        '</div>';
    });
    listEl.innerHTML = html;

    // Attach delete handlers
    listEl.querySelectorAll('.passkey-delete-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        deleteCredential(btn.dataset.id, btn.dataset.name);
      });
    });
  }

  async function deleteCredential(id, name) {
    if (!confirm('Remove passkey "' + name + '"? You will no longer be able to sign in with it.')) {
      return;
    }

    try {
      var resp = await Bugzilla.API.delete('passkey/credentials/' + id);
      loadCredentials();
    } catch (err) {
      showStatus('Failed to remove passkey: ' + err.message, 'error');
    }
  }

  // Register a new passkey
  if (registerBtn) {
    registerBtn.addEventListener('click', async function () {
      hideStatus();

      var name = nameInput.value.trim();
      if (!name) {
        showStatus('Please enter a name for the passkey.', 'error');
        nameInput.focus();
        return;
      }

      // Check for WebAuthn support
      if (!window.PublicKeyCredential) {
        showStatus('Your browser does not support passkeys.', 'error');
        return;
      }

      registerBtn.disabled = true;
      registerBtn.textContent = 'Waiting for passkey…';

      try {
        // Step 1: Get registration options
        var beginData = await Bugzilla.API.post('passkey/register/begin', {name: name});

        var options = beginData.options;
        options.challenge = base64urlToBuffer(options.challenge);
        options.user.id = base64urlToBuffer(options.user.id);

        if (options.excludeCredentials) {
          options.excludeCredentials = options.excludeCredentials.map(function (c) {
            return {type: c.type, id: base64urlToBuffer(c.id)};
          });
        }

        // Step 2: Create credential via browser API
        var credential = await navigator.credentials.create({publicKey: options});

        // Step 3: Send attestation to server
        await Bugzilla.API.post('passkey/register/complete', {
          passkey_token: beginData.passkey_token,
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          attestationObject: bufferToBase64url(credential.response.attestationObject)
        });

        showStatus('Passkey "' + name + '" registered successfully!', 'success');
        nameInput.value = '';
        loadCredentials();
      } catch (err) {
        if (err.name === 'NotAllowedError') {
          showStatus('Passkey registration was cancelled or timed out.', 'error');
        } else if (err.name === 'InvalidStateError') {
          showStatus('This passkey is already registered.', 'error');
        } else {
          showStatus(err.message || 'Passkey registration failed.', 'error');
        }
      } finally {
        registerBtn.disabled = false;
        registerBtn.textContent = 'Register passkey';
      }
    });
  }

  // Initial load
  loadCredentials();
})();
