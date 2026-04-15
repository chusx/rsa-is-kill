/*
 * oauth_resource_server.c
 *
 * Tiny OAuth 2.0 Resource Server built on libjwt: pulls a JWKS from
 * the authorization server, validates RS256-signed access tokens on
 * every inbound HTTP request, and enforces scope claims. The RSA
 * sign/verify primitive is in `jwt_openssl_sign_verify.c`; this file
 * is the integration point every API server actually runs.
 *
 * Deployed in:
 *   - AWS API Gateway + Cognito user-pool authorizers (RS256 default)
 *   - Google Cloud Endpoints ESPv2 (RS256 JWT from Firebase Auth,
 *     Identity Platform, Google-issued tokens)
 *   - Azure API Management with AAD JWT validation
 *   - Auth0 / Okta / Keycloak / Ping resource-server SDKs
 *   - Every SaaS B2B integration that speaks OAuth — Stripe, Twilio,
 *     Shopify, DocuSign, Salesforce Connected Apps
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <jwt.h>
#include <curl/curl.h>
#include <jansson.h>


static json_t *g_jwks;                 /* refreshed hourly */
static char    g_issuer[256];
static char    g_audience[128];


/* ---- JWKS refresh ---- */
static int
jwks_refresh(const char *jwks_uri)
{
    CURL *c = curl_easy_init();
    struct curl_buf b = { 0 };
    curl_easy_setopt(c, CURLOPT_URL, jwks_uri);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_buf_write);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &b);
    CURLcode r = curl_easy_perform(c);
    curl_easy_cleanup(c);
    if (r != CURLE_OK) return -1;

    json_error_t je;
    json_t *new_jwks = json_loads(b.data, 0, &je);
    free(b.data);
    if (!new_jwks) return -1;
    json_decref(g_jwks);
    g_jwks = new_jwks;
    return 0;
}


/* ---- find signing key matching the JWT kid header ---- */
static json_t *
jwks_find_by_kid(const char *kid)
{
    json_t *keys = json_object_get(g_jwks, "keys");
    size_t i; json_t *k;
    json_array_foreach(keys, i, k) {
        const char *this_kid = json_string_value(json_object_get(k, "kid"));
        if (this_kid && strcmp(this_kid, kid) == 0) return k;
    }
    return NULL;
}


/* ---- per-request validator ---- */
int
validate_access_token(const char *authorization_header,
                       const char *required_scope,
                       char *out_sub, size_t out_sub_len)
{
    if (strncmp(authorization_header, "Bearer ", 7) != 0) return 401;
    const char *bearer = authorization_header + 7;

    /* Peek at header to pick RSA key */
    char *hdr_b64, *payload_b64, *sig_b64;
    if (jwt_split(bearer, &hdr_b64, &payload_b64, &sig_b64) != 0) return 401;

    json_t *hdr = b64url_to_json(hdr_b64);
    const char *alg = json_string_value(json_object_get(hdr, "alg"));
    const char *kid = json_string_value(json_object_get(hdr, "kid"));
    if (!alg || strcmp(alg, "RS256") != 0) return 401;   /* alg-confusion guard */

    json_t *jwk = jwks_find_by_kid(kid);
    if (!jwk) {
        jwks_refresh(g_jwks_uri);               /* rolling kid */
        jwk = jwks_find_by_kid(kid);
        if (!jwk) return 401;
    }

    jwt_t *jwt = NULL;
    if (jwt_decode(&jwt, bearer, jwk_to_pem(jwk), jwk_pem_len(jwk)) != 0) {
        return 401;
    }

    /* iss / aud / exp / nbf guards */
    if (strcmp(jwt_get_grant(jwt, "iss"), g_issuer) != 0)   { jwt_free(jwt); return 401; }
    if (strcmp(jwt_get_grant(jwt, "aud"), g_audience) != 0) { jwt_free(jwt); return 401; }
    time_t now = time(NULL);
    if (jwt_get_grant_int(jwt, "exp") < now)                { jwt_free(jwt); return 401; }
    if (jwt_get_grant_int(jwt, "nbf") > now + 30)           { jwt_free(jwt); return 401; }

    /* scope enforcement */
    const char *scopes = jwt_get_grant(jwt, "scope");
    if (!contains_scope(scopes, required_scope))             { jwt_free(jwt); return 403; }

    strncpy(out_sub, jwt_get_grant(jwt, "sub"), out_sub_len);
    jwt_free(jwt);
    return 200;
}


/* ---- Breakage ----
 *
 * Every RS256-validating JWT resource server trusts exactly one thing:
 * that a valid-looking signature under the advertised JWKS was
 * produced by the authorization server's RSA private key. A factoring
 * attack on any AS's signing key (Auth0 tenant key, Cognito user-pool
 * key, AAD tenant key, Keycloak realm RSA key) lets an attacker mint
 * access tokens with arbitrary `sub`, `scope`, and `aud` values that
 * every resource server in that tenant accepts.
 *
 * This is a devastating breach because it bypasses every scope /
 * tenant / multi-tenant-SaaS boundary at once. RS256 is the default
 * algorithm on ~every hosted OAuth provider, making this the
 * single-largest systemic post-factoring authorization risk.
 */
