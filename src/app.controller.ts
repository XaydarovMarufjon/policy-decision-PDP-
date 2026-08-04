import { Controller, Get, Header } from '@nestjs/common';
import { adminConsoleHtml } from './ui/admin-console';
import { allowDevDefaults, requireSecret } from './common/dev-secret';

const CONSOLE_DISABLED_HTML =
  '<!doctype html><html lang="en"><meta charset="utf-8">' +
  '<title>PDP</title><body style="font-family:system-ui;background:#0b1220;color:#cbd5e1;padding:32px">' +
  '<h1>SentryX PDP</h1><p>The admin console is disabled in this environment.</p>' +
  '<p>Set <code>ALLOW_DEV_DEFAULTS=true</code> to enable it (dev/test only). ' +
  'The PDP API stays available to authenticated callers via <code>X-PDP-Auth</code>.</p></body></html>';

/** Escape a value for embedding inside a double-quoted JS string literal. */
function escapeForJsString(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

@Controller()
export class AppController {
  @Get()
  @Header('Content-Type', 'text/html; charset=utf-8')
  index(): string {
    // The console calls the guarded PDP routes from the browser, so it needs the
    // shared secret. Only serve it (and only then embed the secret) in dev, so
    // the secret never reaches a production browser.
    if (!allowDevDefaults()) {
      return CONSOLE_DISABLED_HTML;
    }

    const secret = requireSecret('PDP_SHARED_SECRET', {
      devDefault: 'pdp-dev-shared-secret',
    });
    return adminConsoleHtml.replace(
      /__PDP_SHARED_SECRET__/g,
      escapeForJsString(secret),
    );
  }
}
