import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { PdpModule } from './pdp/pdp.module';

@Module({
  imports: [PdpModule],
  controllers: [AppController],
})
export class AppModule {}
