import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  ServiceUnavailableException,
  UseGuards,
} from '@nestjs/common';
import { PdpService } from './pdp.service';
import { PdpEnforcementResponse, PdpResponse } from './pdp.types';
import { allowDevDefaults } from '../common/dev-secret';
import { AuditLogService, PdpAuditEvent } from './audit/audit-log.service';
import { PdpAuthGuard } from './security/pdp-auth.guard';

@Controller('pdp')
export class PdpController {
  constructor(
    private readonly pdpService: PdpService,
    private readonly auditLog: AuditLogService,
  ) {}

  @Get('health')
  health() {
    return {
      status: 'ok',
      service: 'pdp',
    };
  }

  @Get('health/live')
  live() {
    return { status: 'ok', service: 'pdp' };
  }

  @Get('health/ready')
  async ready() {
    if (!(await this.pdpService.ready())) {
      throw new ServiceUnavailableException('OPA is not ready');
    }
    return { status: 'ok', service: 'pdp', dependencies: { opa: 'ok' } };
  }

  @Post('evaluate')
  @UseGuards(PdpAuthGuard)
  async evaluate(
    @Body() body: unknown,
    @Query('debug') debug?: string,
  ): Promise<PdpResponse | PdpEnforcementResponse> {
    const response = await this.pdpService.evaluate(body);
    return debug === 'true' && allowDevDefaults()
      ? response
      : this.pdpService.toEnforcementResponse(response);
  }

  @Get('audit')
  @UseGuards(PdpAuthGuard)
  audit(@Query('limit') limit?: string): {
    path: string;
    count: number;
    entries: PdpAuditEvent[];
  } {
    return this.auditLog.listRecent(limit ? Number(limit) : 20);
  }
}
