import { createHash, timingSafeEqual } from 'crypto';

/**
 * Fail-closed secret loader shared by the PDP (Nest) and the PEP (standalone
 * Fastify) processes — plain TS, no Nest dependencies so both can import it.
 *
 * A missing secret refuses to boot in production. A committed dev default is
 * only used when ALLOW_DEV_DEFAULTS=true is set explicitly, and then only with a
 * loud warning — nothing silently falls back to a well-known value.
 */
export function allowDevDefaults(): boolean {
  return process.env.ALLOW_DEV_DEFAULTS === 'true';
}

/**
 * Read a required secret from the environment.
 *   - Set and non-empty  -> returned as-is.
 *   - Unset/empty + ALLOW_DEV_DEFAULTS=true + devDefault given -> warn + return devDefault.
 *   - Otherwise -> throw (refuse to boot).
 */
export function requireSecret(
  name: string,
  opts: { devDefault?: string } = {},
): string {
  const value = process.env[name];
  if (value && value.trim() !== '') {
    return value;
  }

  if (allowDevDefaults() && opts.devDefault !== undefined) {
    // eslint-disable-next-line no-console
    console.warn(
      `[dev-secret] ${name} is unset; using the built-in DEV default because ` +
        `ALLOW_DEV_DEFAULTS=true. Never do this in production.`,
    );
    return opts.devDefault;
  }

  throw new Error(
    `${name} is required (refusing to boot). Set it, or set ALLOW_DEV_DEFAULTS=true for dev.`,
  );
}

/**
 * Constant-time string comparison. Both sides are SHA-256 hashed first so the
 * buffers are always equal length (timingSafeEqual throws on length mismatch)
 * and the raw length is never leaked through timing.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}
