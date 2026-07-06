import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { PdpService } from './pdp.service';
import { PdpResponse } from './pdp.types';
import { AuditLogService, PdpAuditEvent } from './audit/audit-log.service';

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
      opaDecisionUrl: this.pdpService.opaDecisionUrl,
    };
  }

  @Post('evaluate')
  evaluate(@Body() body: unknown): Promise<PdpResponse> {
    return this.pdpService.evaluate(body);
  }

  @Get('audit')
  audit(@Query('limit') limit?: string): {
    path: string;
    count: number;
    entries: PdpAuditEvent[];
  } {
    return this.auditLog.listRecent(limit ? Number(limit) : 20);
  }
}
