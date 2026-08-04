import { Module } from '@nestjs/common';
import { PdpController } from './pdp.controller';
import { PdpService } from './pdp.service';
import { ContextBuilderService } from './context/context-builder.service';
import { MockSourceRepository } from './context/mock-source.repository';
import { identityProviderFactory } from './context/identity/identity.providers';
import { riskProviderFactory } from './context/risk/risk.providers';
import { deviceProviderFactory } from './context/device/device.providers';
import { resourceProviderFactory } from './context/resource/resource.providers';
import { OpaPolicyEngineService } from './policy-engine/opa-policy-engine.service';
import { PolicyAdministratorService } from './policy-administrator/policy-administrator.service';
import { AuditLogService } from './audit/audit-log.service';
import { PdpAuthGuard } from './security/pdp-auth.guard';

@Module({
  controllers: [PdpController],
  providers: [
    PdpService,
    ContextBuilderService,
    MockSourceRepository,
    identityProviderFactory,
    riskProviderFactory,
    deviceProviderFactory,
    resourceProviderFactory,
    OpaPolicyEngineService,
    PolicyAdministratorService,
    AuditLogService,
    PdpAuthGuard,
  ],
})
export class PdpModule {}
