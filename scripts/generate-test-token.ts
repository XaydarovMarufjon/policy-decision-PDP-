/**
 * Local test-token generator for the OIDC identity path.
 *
 * Creates an RSA keypair, writes its public JWKS to dev-keys/jwks.json, and
 * prints a signed JWT that carries Keycloak-style identity claims. This lets
 * you exercise IDENTITY_MODE=oidc end-to-end WITHOUT a running IdP.
 *
 * Usage:
 *   npx tsx scripts/generate-test-token.ts \
 *     --user ali.valiyev --role analyst --department SOC --mfa true
 *
 * Then run the PDP with:
 *   IDENTITY_MODE=oidc \
 *   OIDC_ISSUER=urn:pdp-dev \
 *   OIDC_JWKS_FILE=dev-keys/jwks.json \
 *   OIDC_ROLE_PRIORITY=admin,analyst,auditor,guest \
 *   npm run dev
 *
 * When you get a REAL IdP, drop this script: just set OIDC_ISSUER and
 * OIDC_JWKS_URL to the IdP and send real user tokens. No code changes.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import {
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
  type KeyLike,
  SignJWT,
} from 'jose';

function arg(name: string, fallback: string): string {
  const idx = process.argv.indexOf(`--${name}`);
  return idx !== -1 && process.argv[idx + 1] ? process.argv[idx + 1] : fallback;
}

async function main(): Promise<void> {
  const user = arg('user', 'ali.valiyev');
  const role = arg('role', 'analyst');
  const department = arg('department', 'SOC');
  const mfa = arg('mfa', 'true') === 'true';
  const issuer = arg('issuer', 'urn:pdp-dev');
  const audience = arg('audience', '');
  const ttlSeconds = Number(arg('ttl', '3600'));
  const kid = 'pdp-dev-key';
  const outDir = join(process.cwd(), 'dev-keys');
  const privatePath = join(outDir, 'private.jwk');
  mkdirSync(outDir, { recursive: true });

  // Reuse a stable keypair so previously issued tokens keep verifying and the
  // JWKS on disk always matches the running PDP (mirrors a real IdP rotation).
  let privateKey: KeyLike | Uint8Array;
  let publicJwk: JWK;
  if (existsSync(privatePath)) {
    const stored = JSON.parse(readFileSync(privatePath, 'utf8')) as JWK;
    privateKey = await importJWK(stored, 'RS256');
    const { d, p, q, dp, dq, qi, ...pub } = stored;
    publicJwk = pub;
  } else {
    const pair = await generateKeyPair('RS256', { extractable: true });
    privateKey = pair.privateKey;
    publicJwk = await exportJWK(pair.publicKey);
    const privateJwk = await exportJWK(pair.privateKey);
    writeFileSync(privatePath, JSON.stringify(privateJwk, null, 2));
  }

  const jwks = { keys: [{ ...publicJwk, kid, alg: 'RS256', use: 'sig' }] };
  writeFileSync(join(outDir, 'jwks.json'), JSON.stringify(jwks, null, 2));

  const now = Math.floor(Date.now() / 1000);
  const builder = new SignJWT({
    preferred_username: user,
    realm_access: { roles: [role] },
    department,
    amr: mfa ? ['pwd', 'otp'] : ['pwd'],
  })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuer(issuer)
    .setSubject(user)
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds);

  if (audience) {
    builder.setAudience(audience);
  }

  const token = await builder.sign(privateKey);

  console.log('# JWKS written to dev-keys/jwks.json');
  console.log(`# subject: user=${user} role=${role} dept=${department} mfa=${mfa}`);
  console.log('#');
  console.log('# Run the PDP with:');
  console.log(
    `#   IDENTITY_MODE=oidc OIDC_ISSUER=${issuer} OIDC_JWKS_FILE=dev-keys/jwks.json \\`,
  );
  console.log('#   OIDC_ROLE_PRIORITY=admin,analyst,auditor,guest npm run dev');
  console.log('#');
  console.log('# subject_ref token:');
  console.log(token);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
