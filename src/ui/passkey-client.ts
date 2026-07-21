// script de navegador para passkeys, servido en /passkey/client.js. vanilla js sin
// dependencias: convierte los campos binarios (base64url <-> ArrayBuffer) del formato
// json de simplewebauthn y expone window.passkeyRegister / window.passkeyLogin.
// String.raw para que las regex con backslash sobrevivan al template literal.
export const PASSKEY_CLIENT_JS: string = String.raw`(function () {
  'use strict';

  function b64uToBuf(s) {
    var bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  function bufToB64u(buf) {
    var bytes = new Uint8Array(buf);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function postJson(url, body) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    }).then(function (res) {
      return res
        .json()
        .catch(function () {
          return {};
        })
        .then(function (data) {
          if (!res.ok) throw new Error(data.error || 'error del servidor');
          return data;
        });
    });
  }

  // los campos binarios de las options llegan en base64url; el navegador quiere buffers
  function decodeCreationOptions(options) {
    options.challenge = b64uToBuf(options.challenge);
    options.user.id = b64uToBuf(options.user.id);
    (options.excludeCredentials || []).forEach(function (c) {
      c.id = b64uToBuf(c.id);
    });
    return options;
  }

  function decodeRequestOptions(options) {
    options.challenge = b64uToBuf(options.challenge);
    (options.allowCredentials || []).forEach(function (c) {
      c.id = b64uToBuf(c.id);
    });
    return options;
  }

  function fail(onError, message) {
    if (typeof onError === 'function') onError(message);
    else alert(message);
    return false;
  }

  function messageFor(err) {
    if (err && err.name === 'NotAllowedError') return 'operación cancelada o no permitida';
    if (err && err.name === 'InvalidStateError') return 'esta passkey ya está registrada';
    return err && err.message ? err.message : 'error inesperado con la passkey';
  }

  // registra una passkey nueva para la sesión actual; recarga la página al terminar
  window.passkeyRegister = function (name, onError) {
    if (!window.PublicKeyCredential) {
      return Promise.resolve(fail(onError, 'este navegador no soporta passkeys'));
    }
    var challengeId;
    return postJson('/passkey/register/options')
      .then(function (data) {
        challengeId = data.challengeId;
        return navigator.credentials.create({ publicKey: decodeCreationOptions(data.options) });
      })
      .then(function (cred) {
        var response = {
          id: cred.id,
          rawId: bufToB64u(cred.rawId),
          type: cred.type,
          clientExtensionResults: cred.getClientExtensionResults(),
          response: {
            clientDataJSON: bufToB64u(cred.response.clientDataJSON),
            attestationObject: bufToB64u(cred.response.attestationObject),
            transports: cred.response.getTransports ? cred.response.getTransports() : [],
          },
        };
        if (cred.authenticatorAttachment) response.authenticatorAttachment = cred.authenticatorAttachment;
        return postJson('/passkey/register/verify', { challengeId: challengeId, response: response, name: name });
      })
      .then(function () {
        location.reload();
        return true;
      })
      .catch(function (err) {
        return fail(onError, messageFor(err));
      });
  };

  // serializa la aserción de webauthn al formato json que espera el servidor
  function assertionResponse(cred) {
    var response = {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        authenticatorData: bufToB64u(cred.response.authenticatorData),
        signature: bufToB64u(cred.response.signature),
        userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : undefined,
      },
    };
    if (cred.authenticatorAttachment) response.authenticatorAttachment = cred.authenticatorAttachment;
    return response;
  }

  // pide opciones, obtiene la credencial con la mediación indicada y cierra el login.
  // mediation 'conditional' => autofill: el navegador ofrece las passkeys en el propio
  // campo de usuario sin que haga falta pulsar ningún botón.
  function runLogin(returnTo, mediation, onError) {
    var challengeId;
    return postJson('/passkey/login/options')
      .then(function (data) {
        challengeId = data.challengeId;
        var opts = { publicKey: decodeRequestOptions(data.options) };
        if (mediation) opts.mediation = mediation;
        return navigator.credentials.get(opts);
      })
      .then(function (cred) {
        if (!cred) return false; // el autofill se abortó sin elegir passkey
        return postJson('/passkey/login/verify', {
          challengeId: challengeId,
          response: assertionResponse(cred),
          returnTo: returnTo,
        }).then(function (data) {
          location.assign(data.returnTo || '/account');
          return true;
        });
      })
      .catch(function (err) {
        if (onError === false) return false; // modo silencioso (autofill)
        return fail(onError, messageFor(err));
      });
  }

  // login explícito (botón): abre el selector de passkeys del navegador
  window.passkeyLogin = function (returnTo, onError) {
    if (!window.PublicKeyCredential) {
      return Promise.resolve(fail(onError, 'este navegador no soporta passkeys'));
    }
    return runLogin(returnTo, undefined, onError);
  };

  // login por autofill: se arranca solo al cargar la página de login. si el navegador
  // no soporta mediación condicional, no hace nada (queda el botón como alternativa).
  window.passkeyConditional = function (returnTo) {
    if (!window.PublicKeyCredential || !window.PublicKeyCredential.isConditionalMediationAvailable) return;
    window.PublicKeyCredential.isConditionalMediationAvailable().then(function (available) {
      if (available) runLogin(returnTo, 'conditional', false);
    });
  };
})();
`;
