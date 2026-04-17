/*
 * rp_server_auth_flow.ts
 *
 * WebAuthn Relying Party (RP) server — registration + authentication
 * ceremony orchestration. The RS256 (RSA-PKCS#1 v1.5) attestation
 * statement parser + verifier is the Rust crate alongside
 * (`webauthn_rs256_attestation.rs`); this file is the HTTP/app glue
 * that drives the ceremony for real RPs.
 *
 * Deployed as the auth backbone at: GitHub, Google (Advanced
 * Protection Program), Microsoft entra-id passkeys, Cloudflare Zero
 * Trust, Okta passwordless, Duo Universal Prompt, Shopify staff,
 * Coinbase, every passkey-enabled banking portal.  Packet Library:
 * SimpleWebAuthn (~4M downloads/wk), WebAuthn4J, Webauthn.java (Yubico).
 */

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

import { verifyRs256AttestationStatement } from "./rust_ffi";   // -> webauthn_rs256_attestation.rs

const rpID     = "auth.example.com";
const rpName   = "Example, Inc.";
const origin   = `https://${rpID}`;

// ---- 1. Registration (attestation) ----

export async function beginRegistration(userId: string, userName: string) {
  const user = await db.user.get(userId);
  const opts = await generateRegistrationOptions({
    rpID, rpName,
    userID: Buffer.from(userId),
    userName,
    attestationType: "direct",                // we WANT the attestation for FIDO MDS match
    supportedAlgorithmIDs: [-7, -8, -257],    // ES256, EdDSA, RS256
    authenticatorSelection: {
      residentKey:         "required",        // passkey (discoverable)
      userVerification:    "required",
    },
    excludeCredentials: user.credentials.map(c => ({ id: c.credentialID, type: "public-key" })),
  });
  await db.challenge.put(userId, opts.challenge);
  return opts;
}

export async function finishRegistration(userId: string, body: any) {
  const expectedChallenge = await db.challenge.take(userId);
  const v = await verifyRegistrationResponse({
    response:           body,
    expectedChallenge,
    expectedOrigin:     origin,
    expectedRPID:       rpID,
    requireUserVerification: true,
  });
  if (!v.verified) throw new Error("attestation verify failed");

  // For authenticators returning RS256 "packed" or "tpm" attestation
  // (Windows Hello TPM-backed, older YubiKey NEO firmware, many
  // enterprise platform authenticators), route into the RSA-PKCS1v15
  // path. YubiKey 5 series / Apple / Google Titan return ES256 packed
  // and skip this path entirely.
  const fmt = v.registrationInfo!.fmt;
  if (fmt === "packed" && v.registrationInfo!.aaguid) {
    await verifyRs256AttestationStatement(
      body.response.attestationObject,
      body.response.clientDataJSON,
      fidoMds.lookup(v.registrationInfo!.aaguid),   // FIDO Metadata Service entry
    );
  }

  await db.user.addCredential(userId, {
    credentialID:     v.registrationInfo!.credentialID,
    credentialPublicKey: v.registrationInfo!.credentialPublicKey,
    counter:          v.registrationInfo!.counter,
    transports:       body.response.transports,
    aaguid:           v.registrationInfo!.aaguid,
    attestationFmt:   fmt,
  });
}

// ---- 2. Authentication (assertion) ----

export async function beginLogin(userId: string) {
  const user = await db.user.get(userId);
  const opts = await generateAuthenticationOptions({
    rpID,
    allowCredentials: user.credentials.map(c => ({ id: c.credentialID, type: "public-key" })),
    userVerification: "required",
  });
  await db.challenge.put(userId, opts.challenge);
  return opts;
}

export async function finishLogin(userId: string, body: any) {
  const user = await db.user.get(userId);
  const cred = user.credentials.find(c => c.credentialID.equals(body.id));
  if (!cred) throw new Error("unknown credential");

  const v = await verifyAuthenticationResponse({
    response:           body,
    expectedChallenge:  await db.challenge.take(userId),
    expectedOrigin:     origin,
    expectedRPID:       rpID,
    authenticator:      cred,
    requireUserVerification: true,
  });
  if (!v.verified) throw new Error("assertion verify failed");
  // Signature counter rollback check
  if (v.authenticationInfo.newCounter <= cred.counter && cred.counter !== 0)
    throw new Error("authenticator clone suspected");
  await db.user.updateCounter(userId, cred.credentialID, v.authenticationInfo.newCounter);
  return user;
}

// ---- Breakage ----
//
// WebAuthn is a mixed algorithm zone. Platform authenticators and older
// YubiKeys use RS256 (RSA-2048 PKCS#1 v1.5); newer authenticators use
// ES256 / EdDSA. A factoring break:
//   - Lets an attacker forge assertions for any RS256 credential —
//     silent account takeover against every RP that accepts RS256
//     (most do, since all major browsers negotiate it).
//   - Forges attestation for the "packed" and "tpm" formats, bypassing
//     enterprise authenticator-model allowlists.
//
// RPs that negotiate ES256-only survive the break; RPs that enforce
// attestation via FIDO MDS and only trust ES256-rooted AAGUIDs survive.
// Most of the consumer web today accepts RS256 and is therefore fully
// exposed.
