import { describe, expect, it } from "vitest";

import {
  decodeCreationOptions,
  decodeRequestOptions,
  encodeAssertionResponse,
  encodeAttestationResponse
} from "@/lib/webauthn";

function bytes(...values: number[]): ArrayBuffer {
  return new Uint8Array(values).buffer;
}

function toArray(buffer: ArrayBuffer | ArrayBufferView): number[] {
  const view = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer);
  return Array.from(view);
}

describe("decodeCreationOptions", () => {
  it("decodes base64url challenge, user id and excluded credentials", () => {
    const options = decodeCreationOptions({
      publicKey: {
        rp: { name: "Portlyn" },
        challenge: "AQIDBA",
        user: { id: "BQYH", name: "admin", displayName: "Admin" },
        excludeCredentials: [{ type: "public-key", id: "CAkK", transports: ["internal"] }]
      }
    });

    expect(toArray(options.challenge as ArrayBuffer)).toEqual([1, 2, 3, 4]);
    expect(toArray(options.user.id as ArrayBuffer)).toEqual([5, 6, 7]);
    expect(options.excludeCredentials).toHaveLength(1);
    expect(toArray(options.excludeCredentials![0].id as ArrayBuffer)).toEqual([8, 9, 10]);
    expect(options.rp.name).toBe("Portlyn");
  });

  it("handles a missing excludeCredentials list", () => {
    const options = decodeCreationOptions({
      publicKey: { challenge: "AQID", user: { id: "AQID", name: "a", displayName: "a" } }
    });
    expect(options.excludeCredentials).toEqual([]);
  });
});

describe("decodeRequestOptions", () => {
  it("decodes challenge and allowed credentials", () => {
    const options = decodeRequestOptions({
      publicKey: {
        challenge: "__8",
        allowCredentials: [{ type: "public-key", id: "AQID", transports: ["usb"] }]
      }
    });

    expect(toArray(options.challenge as ArrayBuffer)).toEqual([255, 255]);
    expect(toArray(options.allowCredentials![0].id as ArrayBuffer)).toEqual([1, 2, 3]);
  });
});

describe("encodeAttestationResponse", () => {
  it("encodes buffers as unpadded base64url", () => {
    const encoded = encodeAttestationResponse({
      id: "credential-id",
      rawId: bytes(255, 255),
      type: "public-key",
      response: {
        attestationObject: bytes(1, 2, 3),
        clientDataJSON: bytes(5, 6, 7)
      }
    } as unknown as PublicKeyCredential);

    expect(encoded.id).toBe("credential-id");
    expect(encoded.rawId).toBe("__8");
    expect(encoded.rawId).not.toContain("=");
    expect(encoded.response.attestationObject).toBe("AQID");
    expect(encoded.response.clientDataJSON).toBe("BQYH");
  });
});

describe("encodeAssertionResponse", () => {
  it("encodes every part of the assertion", () => {
    const encoded = encodeAssertionResponse({
      id: "credential-id",
      rawId: bytes(1, 2, 3),
      type: "public-key",
      response: {
        authenticatorData: bytes(1, 2, 3),
        clientDataJSON: bytes(5, 6, 7),
        signature: bytes(8, 9, 10),
        userHandle: bytes(255, 255)
      }
    } as unknown as PublicKeyCredential);

    expect(encoded.response.authenticatorData).toBe("AQID");
    expect(encoded.response.signature).toBe("CAkK");
    expect(encoded.response.userHandle).toBe("__8");
  });

  it("keeps a missing user handle as null", () => {
    const encoded = encodeAssertionResponse({
      id: "credential-id",
      rawId: bytes(1),
      type: "public-key",
      response: {
        authenticatorData: bytes(1),
        clientDataJSON: bytes(1),
        signature: bytes(1),
        userHandle: null
      }
    } as unknown as PublicKeyCredential);

    expect(encoded.response.userHandle).toBeNull();
  });
});

describe("webauthn round trip", () => {
  it("survives decode followed by encode", () => {
    const original = [1, 2, 3, 250, 251, 252];
    const options = decodeCreationOptions({
      publicKey: { challenge: "AQID+vv8", user: { id: "AQID", name: "a", displayName: "a" } }
    });
    expect(toArray(options.challenge as ArrayBuffer)).toEqual(original);
  });
});
