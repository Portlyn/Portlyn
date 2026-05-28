function base64URLToBuffer(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(value.length + ((4 - (value.length % 4)) % 4), "=");
  const binary = atob(padded);
  const buf = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < binary.length; i++) {
    view[i] = binary.charCodeAt(i);
  }
  return buf;
}

function bufferToBase64URL(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeCreationOptions(options: any): PublicKeyCredentialCreationOptions {
  const challenge = base64URLToBuffer(options.publicKey.challenge);
  const userId = base64URLToBuffer(options.publicKey.user.id);
  const excludeCredentials = (options.publicKey.excludeCredentials || []).map((cred: any) => ({
    type: cred.type,
    id: base64URLToBuffer(cred.id),
    transports: cred.transports,
  }));
  return {
    ...options.publicKey,
    challenge,
    user: { ...options.publicKey.user, id: userId },
    excludeCredentials,
  };
}

export function encodeAttestationResponse(credential: PublicKeyCredential): any {
  const attestation = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64URL(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64URL(attestation.attestationObject),
      clientDataJSON: bufferToBase64URL(attestation.clientDataJSON),
    },
  };
}

export function decodeRequestOptions(options: any): PublicKeyCredentialRequestOptions {
  const challenge = base64URLToBuffer(options.publicKey.challenge);
  const allowCredentials = (options.publicKey.allowCredentials || []).map((cred: any) => ({
    type: cred.type,
    id: base64URLToBuffer(cred.id),
    transports: cred.transports,
  }));
  return {
    ...options.publicKey,
    challenge,
    allowCredentials,
  };
}

export function encodeAssertionResponse(credential: PublicKeyCredential): any {
  const assertion = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64URL(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64URL(assertion.authenticatorData),
      clientDataJSON: bufferToBase64URL(assertion.clientDataJSON),
      signature: bufferToBase64URL(assertion.signature),
      userHandle: assertion.userHandle ? bufferToBase64URL(assertion.userHandle) : null,
    },
  };
}
