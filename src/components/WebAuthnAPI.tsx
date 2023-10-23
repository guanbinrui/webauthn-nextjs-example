"use client";

import { useMount } from "@/hooks/useMount";
import { decode } from "cbor";
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { AsnParser } from "@peculiar/asn1-schema";

export function WebAuthnAPI() {
  const mounted = useMount();
  if (!mounted) return null;

  return (
    <>
      <h1 className="mt-8">WebAuthnAPI</h1>

      <p>
        <a href="https://www.iana.org/assignments/cose/cose.xhtml">COSE</a>
      </p>

      <button
        onClick={async () => {
          const challenge = new Uint8Array(32);
          crypto.getRandomValues(challenge);

          const userId = "Kosv9fPtkDoh4Oz7Yq/pVgWHS8HhdlCto5cR0aBoVMw=";
          const id = Uint8Array.from(atob(userId), (c) => c.charCodeAt(0));

          const creationOptions: PublicKeyCredentialCreationOptions = {
            challenge,

            rp: {
              name: "Example Project",
            },

            user: {
              id,
              name: "alice@example.com",
              displayName: "Alice",
            },

            pubKeyCredParams: [
              { type: "public-key", alg: -7 }, // ES256
              { type: "public-key", alg: -257 }, // RS256
            ],
          };

          // Create a credential on the client side
          const credential = await navigator.credentials.create({
            publicKey: creationOptions,
          });
          if (!credential) throw new Error("Failed to create credential");

          console.log("[DEBUG] Credential created.");
          console.log(credential);

          // The server should parse client data JSON & validate it
          const decoder = new TextDecoder("utf-8");

          const clientDataJSON = JSON.parse(
            // @ts-ignore
            decoder.decode(credential.response.clientDataJSON)
          );

          console.log("[DEBUG] Client Data JSON");
          console.log(clientDataJSON);

          // validate data type
          if (clientDataJSON.type !== "webauthn.create")
            throw new Error("Invalid client data type");

          // validate challenge
          if (
            Buffer.from(clientDataJSON.challenge, "base64").toString(
              "base64"
            ) !== Buffer.from(challenge).toString("base64")
          )
            throw new Error("Invalid client data challenge");

          // The attestationObject was was encoded as CBOR.
          const attestationObject = decode(
            // @ts-ignore
            credential.response.attestationObject
          );

          console.log("[DEBUG] Attestation Object");
          console.log(attestationObject);

          const authData = attestationObject.authData as Buffer;
          const dataView = new DataView(new ArrayBuffer(2));
          const idLenBytes = authData.slice(53, 55);
          idLenBytes.forEach((value, index) => dataView.setUint8(index, value));
          const credentialIdLength = dataView.getUint16(0);

          // get the credential ID
          const credentialId = authData.slice(55, 55 + credentialIdLength);

          // validate the credential ID
          if (
            Buffer.from(credentialId).toString("base64") !==
            // @ts-ignore
            Buffer.from(credential.rawId as ArrayBuffer).toString("base64")
          )
            throw new Error("Invalid credential ID");

          // get the public key object
          const publicKeyBytes = authData.slice(55 + credentialIdLength);

          // the publicKeyBytes are encoded again as CBOR
          const publicKeyObject = decode(publicKeyBytes);

          console.log("[DEBUG] Public Key Object");
          console.log(publicKeyObject);

          // Sign a random challenge
          const signChallenge = new Uint8Array(32);
          crypto.getRandomValues(challenge);

          const signOptions: PublicKeyCredentialRequestOptions = {
            challenge: signChallenge,
            allowCredentials: [
              {
                id: credentialId,
                type: "public-key",
              },
            ],
          };

          const signCredential = await navigator.credentials.get({
            publicKey: signOptions,
          });

          console.log("[DEBUG] Credential signed.");
          console.log(signCredential);

          // Parse user handler
          const handler = Buffer.from(
            // @ts-ignore
            signCredential.response.userHandle
          ).toString("base64");
          if (handler !== userId) throw new Error("Invalid user handler");

          console.log("[DEBUG] User Handle");
          console.log(handler);

          // The data to be verified with the signature.
          const data = Buffer.concat([
            // @ts-ignore
            Buffer.from(signCredential.response.authenticatorData),
            // @ts-ignore
            Buffer.from(
              await crypto.subtle.digest(
                "SHA-256",
                // @ts-ignore
                signCredential.response.clientDataJSON
              )
            ),
          ]);

          // In WebAuthn, EC2 signatures are wrapped in ASN.1 structure so we need to peel r and s apart.
          // @ts-ignore
          const parsedSignature = AsnParser.parse(
            // @ts-ignore
            signCredential.response.signature,
            ECDSASigValue
          );

          let rBytes = new Uint8Array(parsedSignature.r);
          let sBytes = new Uint8Array(parsedSignature.s);

          if (shouldRemoveLeadingZero(rBytes)) {
            rBytes = rBytes.slice(1);
          }

          if (shouldRemoveLeadingZero(sBytes)) {
            sBytes = sBytes.slice(1);
          }

          const finalSignature = Buffer.concat([
            Buffer.from(rBytes),
            Buffer.from(sBytes),
          ]);

          // Import the public key, it could obtain from the AuthenticatorAssertionResponse as well.
          const key = await crypto.subtle.importKey(
            "jwk",
            {
              kty: "EC",
              crv: "P-256",
              x: toBase64URL(publicKeyObject.get(-2)),
              y: toBase64URL(publicKeyObject.get(-3)),
              ext: true,
            },
            {
              name: "ECDSA",
              namedCurve: "P-256",
            },
            true,
            ["verify"]
          );

          // Verify the signature
          const verified = await crypto.subtle.verify(
            {
              name: "ECDSA",
              hash: { name: "SHA-256" },
            },
            key,
            finalSignature,
            data
          );

          console.log("[DEBUG] Signature verification result");
          console.log(verified);
        }}
      >
        Action
      </button>
    </>
  );
}

function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}

function toBase64URL(bytes: ArrayBuffer) {
  return Buffer.from(bytes)
    .toString("base64")
    .replace("+", "-")
    .replace("/", "_")
    .replace(/=+$/, "");
}
