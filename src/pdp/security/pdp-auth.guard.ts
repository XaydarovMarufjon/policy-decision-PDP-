import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { FastifyRequest } from 'fastify';
import { constantTimeEqual, requireSecret } from '../../common/dev-secret';

/**
 * Shared-secret guard for the sensitive PDP routes (/pdp/evaluate, /pdp/audit).
 * Callers (the PEP, the admin console) must send the secret in the `X-PDP-Auth`
 * header. This is the PEP<->PDP trust boundary — without it, anyone able to
 * reach the PDP port could request decisions or read the audit log.
 *
 * The secret is resolved once at construction via requireSecret(), so the PDP
 * fails closed at boot in production if PDP_SHARED_SECRET is unset.
 */
export const PDP_AUTH_HEADER = 'x-pdp-auth';

@Injectable()
export class PdpAuthGuard implements CanActivate {
  private readonly logger = new Logger(PdpAuthGuard.name);
  private readonly secret = requireSecret('PDP_SHARED_SECRET', {
    devDefault: 'pdp-dev-shared-secret',
  });

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const header = request.headers[PDP_AUTH_HEADER];
    const provided = Array.isArray(header) ? header[0] : header;

    if (!provided || !constantTimeEqual(provided, this.secret)) {
      this.logger.warn(
        `Rejected ${request.method} ${request.url}: missing or invalid ${PDP_AUTH_HEADER}`,
      );
      throw new UnauthorizedException('Invalid or missing PDP shared secret');
    }

    return true;
  }
}
