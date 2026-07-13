import { Injectable, Logger } from '@nestjs/common';
import { readFileSync } from 'fs';
import * as jose from 'jose';
import { SubjectContext, SubjectRef } from '../../pdp.types';
import { IdentityProvider, IdentityResolution } from './identity-provider';

type JwtPayload = Record<string, unknown>;

/**
 * Real identity provider. Verifies a JWT issued by an OpenID Connect Identity
 * Provider (Keycloak, Entra, Okta, ...) against its JWKS, then maps standard
 * and Keycloak-style claims into the PDP canonical subject.
 *
 * Enabled with IDENTITY_MODE=oidc. Configuration (env):
 *   OIDC_ISSUER            expected `iss` claim, e.g. https://kc/realms/soc
 *   OIDC_JWKS_URL          remote JWKS endpoint (default: <issuer>/protocol/openid-connect/certs)
 *   OIDC_JWKS_FILE         local JWKS JSON file (offline testing; overrides JWKS_URL)
 *   OIDC_AUDIENCE          expected `aud` (optional)
 *   OIDC_CLAIM_USER        username claim path (default preferred_username)
 *   OIDC_CLAIM_ROLE        role claim path (default realm_access.roles)
 *   OIDC_ROLE_PRIORITY     comma list; first match wins when role claim is an array
 *   OIDC_DEFAULT_ROLE      fallback role when none present
 *   OIDC_CLAIM_DEPARTMENT  department claim path (default department)
 *   OIDC_DEFAULT_DEPARTMENT fallback department when claim absent
 *   OIDC_CLAIM_MFA         mfa claim path (default amr)
 *   OIDC_MFA_MARKERS       comma list treated as "mfa satisfied" (default mfa,otp,hwk,totp,mca,sms)
 *   OIDC_MFA_ACR_VALUES    comma list of acr values that satisfy mfa
 */
@Injectable()
export class OidcIdentityProvider implements IdentityProvider {
  readonly mode = 'oidc' as const;

  private readonly logger = new Logger(OidcIdentityProvider.name);

  private readonly issuer = this.env('OIDC_ISSUER');
  private readonly audience = this.env('OIDC_AUDIENCE');
  private readonly userClaim = this.env('OIDC_CLAIM_USER') ?? 'preferred_username';
  private readonly roleClaim = this.env('OIDC_CLAIM_ROLE') ?? 'realm_access.roles';
  private readonly rolePriority = this.list(this.env('OIDC_ROLE_PRIORITY'));
  private readonly defaultRole = this.env('OIDC_DEFAULT_ROLE');
  private readonly deptClaim = this.env('OIDC_CLAIM_DEPARTMENT') ?? 'department';
  private readonly defaultDept = this.env('OIDC_DEFAULT_DEPARTMENT');
  private readonly mfaClaim = this.env('OIDC_CLAIM_MFA') ?? 'amr';
  private readonly mfaMarkers = this.list(
    this.env('OIDC_MFA_MARKERS') ?? 'mfa,otp,hwk,totp,mca,sms',
  ).map((m) => m.toLowerCase());
  private readonly mfaAcrValues = this.list(this.env('OIDC_MFA_ACR_VALUES'));

  private readonly jwks: jose.JWTVerifyGetKey;
  private readonly jwksLabel: string;

  constructor() {
    if (!this.issuer) {
      throw new Error(
        'IDENTITY_MODE=oidc requires OIDC_ISSUER to be set (expected token issuer).',
      );
    }

    const jwksFile = this.env('OIDC_JWKS_FILE');
    if (jwksFile) {
      const raw = JSON.parse(readFileSync(jwksFile, 'utf8'));
      this.jwks = jose.createLocalJWKSet(raw);
      this.jwksLabel = `oidc:file:${jwksFile}`;
    } else {
      const jwksUrl =
        this.env('OIDC_JWKS_URL') ??
        `${this.issuer.replace(/\/$/, '')}/protocol/openid-connect/certs`;
      this.jwks = jose.createRemoteJWKSet(new URL(jwksUrl));
      this.jwksLabel = `oidc:${jwksUrl}`;
    }

    this.logger.log(
      `OIDC identity provider active (issuer=${this.issuer}, jwks=${this.jwksLabel})`,
    );
  }

  async resolveSubject(ref: SubjectRef): Promise<IdentityResolution> {
    const base: IdentityResolution = {
      adapter: this.jwksLabel,
      lookupKey: this.lookupKey(ref),
      issuer: this.issuer,
    };

    const token = ref.token;
    if (!token || (ref.type !== 'jwt' && ref.type !== 'mock_token')) {
      return {
        ...base,
        error: 'OIDC identity requires subject_ref.type=jwt with a token',
      };
    }

    try {
      const { payload } = await jose.jwtVerify(token, this.jwks, {
        issuer: this.issuer,
        audience: this.audience,
      });

      const subject = this.mapClaims(payload);
      if (!subject) {
        return {
          ...base,
          lookupKey: this.subLookupKey(payload, ref),
          error:
            'JWT verified but required identity claims (user/role/department) are missing',
        };
      }

      return { ...base, lookupKey: this.subLookupKey(payload, ref), subject };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { ...base, error: `JWT verification failed: ${message}` };
    }
  }

  private mapClaims(payload: JwtPayload): SubjectContext | undefined {
    const user =
      this.str(this.getPath(payload, this.userClaim)) ??
      this.str(payload.sub);
    const role = this.extractRole(payload);
    const department =
      this.str(this.getPath(payload, this.deptClaim)) ?? this.defaultDept;

    if (!user || !role || !department) {
      return undefined;
    }

    return {
      user,
      role,
      department,
      mfa: this.extractMfa(payload),
    };
  }

  private extractRole(payload: JwtPayload): string | undefined {
    const raw = this.getPath(payload, this.roleClaim);

    if (Array.isArray(raw)) {
      const roles = raw.map((r) => this.str(r)).filter((r): r is string => !!r);
      for (const preferred of this.rolePriority) {
        if (roles.includes(preferred)) {
          return preferred;
        }
      }
      return roles[0] ?? this.defaultRole;
    }

    return this.str(raw) ?? this.defaultRole;
  }

  private extractMfa(payload: JwtPayload): boolean {
    const raw = this.getPath(payload, this.mfaClaim);

    if (typeof raw === 'boolean') {
      return raw;
    }

    if (Array.isArray(raw)) {
      return raw.some((v) => this.mfaMarkers.includes(String(v).toLowerCase()));
    }

    if (typeof raw === 'string') {
      const lower = raw.toLowerCase();
      return (
        this.mfaAcrValues.includes(raw) || this.mfaMarkers.includes(lower)
      );
    }

    return false;
  }

  /** Resolve a dot-separated claim path (e.g. "realm_access.roles"). */
  private getPath(payload: JwtPayload, path: string): unknown {
    return path.split('.').reduce<unknown>((acc, key) => {
      if (acc && typeof acc === 'object' && key in (acc as object)) {
        return (acc as Record<string, unknown>)[key];
      }
      return undefined;
    }, payload);
  }

  private str(value: unknown): string | undefined {
    return typeof value === 'string' && value.trim() !== '' ? value : undefined;
  }

  /** Read an env var, treating unset OR empty string as undefined. */
  private env(name: string): string | undefined {
    const value = process.env[name];
    return value && value.trim() !== '' ? value : undefined;
  }

  private list(value: string | undefined): string[] {
    return (value ?? '')
      .split(',')
      .map((v) => v.trim())
      .filter((v) => v !== '');
  }

  private subLookupKey(payload: JwtPayload, ref: SubjectRef): string {
    const sub = this.str(payload.sub);
    const user = this.str(this.getPath(payload, this.userClaim));
    return `oidc:${user ?? sub ?? this.mask(ref.token)}`;
  }

  private lookupKey(ref: SubjectRef): string {
    return `${ref.type}:${this.mask(ref.token)}`;
  }

  private mask(value: string | undefined): string {
    if (!value) {
      return '<missing>';
    }

    if (value.length <= 8) {
      return '***';
    }

    return `${value.slice(0, 4)}...${value.slice(-4)}`;
  }
}
