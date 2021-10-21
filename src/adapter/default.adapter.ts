import { AbstractKeycloak } from '../index';
import {
  KeycloakLoginOptions,
  KeycloakRegisterOptions,
} from '../options/login-options';
import { KeycloakLogoutOptions } from '../options/logout-options';

export class DefaultAdapter extends AbstractKeycloak {
  login(options: KeycloakLoginOptions) {
    window.location.replace(this.createLoginUrl(options));
    return Promise.resolve();
  }

  logout(options: KeycloakLogoutOptions) {
    window.location.replace(this.createLogoutUrl(options));
    return Promise.resolve();
  }

  register(options: KeycloakRegisterOptions) {
    window.location.replace(this.createRegisterUrl(options));
    return Promise.resolve();
  }

  accountManagement() {
    var accountUrl = this.createAccountUrl();
    if (typeof accountUrl !== 'undefined') {
      window.location.href = accountUrl;
    } else {
      throw 'Not supported by the OIDC server';
    }
    return Promise.resolve();
  }

  redirectUri(options: { redirectUri: string }) {
    if (options && options.redirectUri) {
      return options.redirectUri;
    } else if (this.options?.redirectUri) {
      return this.options?.redirectUri;
    } else {
      return location.href;
    }
  }
}
