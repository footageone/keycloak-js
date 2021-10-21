import { KeycloakRoles } from './roles';
import { KeycloakResourceAccess } from './resource-access';

export type KeycloakOnLoad = 'login-required' | 'check-sso';
export type KeycloakResponseMode = 'query' | 'fragment';
export type KeycloakResponseType =
  | 'code'
  | 'id_token token'
  | 'code id_token token';
export type KeycloakFlow = 'standard' | 'implicit' | 'hybrid';
export type KeycloakPkceMethod = 'S256';

export interface KeycloakProfile {
  id?: string;
  username?: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  enabled?: boolean;
  emailVerified?: boolean;
  totp?: boolean;
  createdTimestamp?: number;
}

export interface KeycloakError {
  error: string;
  error_description: string;
}

export interface KeycloakAccountOptions {
  /**
   * Specifies the uri to redirect to when redirecting back to the application.
   */
  redirectUri?: string;
}
