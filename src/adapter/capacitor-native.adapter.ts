import { AbstractKeycloak } from '../index';
import { createPromise } from '../create-promise';
import { CapacitorAdapter } from './capacitor.adapter';
import { App } from '@capacitor/app';

export class CapacitorNativeAdapter extends CapacitorAdapter {
  login(options) {
    var promise = createPromise<void, any>();
    var loginUrl = this.createLoginUrl(options);

    App.addListener('appUrlOpen', (data) => {
      var oauth = this.parseCallback(data.url);
      this.processCallback(oauth, promise);
    });

    window.open(loginUrl, '_system');
    return promise.promise;
  }

  logout(options) {
    var promise = createPromise<void, any>();
    var logoutUrl = this.createLogoutUrl(options);

    App.addListener('appUrlOpen', (data) => {
      this.clearToken();
      promise.setSuccess();
    });

    window.open(logoutUrl, '_system');
    return promise.promise;
  }

  register(options) {
    var promise = createPromise<void, any>();
    var registerUrl = this.createRegisterUrl(options);
    App.addListener('appUrlOpen', (data) => {
      var oauth = this.parseCallback(data.url);
      this.processCallback(oauth, promise);
    });
    window.open(registerUrl, '_system');
    return promise.promise;
  }

  accountManagement() {
    var accountUrl = this.createAccountUrl();
    if (typeof accountUrl !== 'undefined') {
      window.open(accountUrl, '_system');
      return Promise.resolve();
    } else {
      throw 'Not supported by the OIDC server';
    }
  }
}
