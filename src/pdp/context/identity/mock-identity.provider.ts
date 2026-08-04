import { Injectable } from '@nestjs/common';
import { SubjectRef } from '../../pdp.types';
import { MockSourceRepository } from '../mock-source.repository';
import { IdentityProvider, IdentityResolution } from './identity-provider';

/**
 * Default identity provider. Resolves the subject from the local
 * mock-sources/identity.json file. Used when IDENTITY_MODE=mock (default),
 * so the stack keeps running without a real IdP.
 */
@Injectable()
export class MockIdentityProvider implements IdentityProvider {
  readonly mode = 'mock' as const;

  constructor(private readonly sources: MockSourceRepository) {}

  async resolveSubject(ref: SubjectRef): Promise<IdentityResolution> {
    const subject = this.sources.resolveSubject(ref);

    return {
      subject,
      adapter: 'mock-sources/identity.json',
      lookupKey: this.lookupKey(ref),
    };
  }

  private lookupKey(ref: SubjectRef): string {
    if (ref.type === 'jwt' || ref.type === 'mock_token') {
      return `${ref.type}:${this.mask(ref.token)}`;
    }

    return `${ref.type}:${ref.user_id ?? '<missing>'}`;
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
