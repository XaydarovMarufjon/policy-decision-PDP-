import { Controller, Get, Header } from '@nestjs/common';
import { adminConsoleHtml } from './ui/admin-console';

@Controller()
export class AppController {
  @Get()
  @Header('Content-Type', 'text/html; charset=utf-8')
  index(): string {
    return adminConsoleHtml;
  }
}
