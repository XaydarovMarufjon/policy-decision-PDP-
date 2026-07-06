import { Module } from '@nestjs/common';
import { PdpController } from './pdp.controller';
import { PdpService } from './pdp.service';
import { ContextBuilderService } from './context/context-builder.service';
import { MockSourceRepository } from './context/mock-source.repository';
import { OpaPolicyEngineService } from './policy-engine/opa-policy-engine.service';
import { PolicyAdministratorService } from './policy-administrator/policy-administrator.service';
import { AuditLogService } from './audit/audit-log.service';

@Module({
  controllers: [PdpController],
  providers: [
    PdpService,
    ContextBuilderService,
    MockSourceRepository,
    OpaPolicyEngineService,
    PolicyAdministratorService,
    AuditLogService,
  ],
})
export class PdpModule {}
