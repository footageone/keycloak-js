import { AbstractKeycloak } from '../index';
import { createPromise } from '../create-promise';
import { App } from '@capacitor/app';

export class CapacitorAdapter extends AbstractKeycloak {
  login(options) {
    var promise = createPromise<void, any>();
    var loginUrl = this.createLoginUrl(options);

    App.addListener('appUrlOpen', (data) => {
      window.cordova.plugins.browsertab.close();
      var oauth = this.parseCallback(data.url);
      this.processCallback(oauth, promise);
    });

    window.cordova.plugins.browsertab.openUrl(loginUrl);
    return promise.promise;
  }

  logout(options) {
    const promise = createPromise<void, any>();
    var logoutUrl = this.createLogoutUrl(options);

    App.addListener('appUrlOpen', (data) => {
      window.cordova.plugins.browsertab.close();
      this.clearToken();
      promise.setSuccess();
    });

    window.cordova.plugins.browsertab.openUrl(logoutUrl);
    return promise.promise;
  }

  register(options) {
    const promise = createPromise<void, any>();
    var registerUrl = this.createRegisterUrl(options);
    App.addListener('appUrlOpen', (data) => {
      window.cordova.plugins.browsertab.close();
      var oauth = this.parseCallback(data.url);
      this.processCallback(oauth, promise);
    });
    window.cordova.plugins.browsertab.openUrl(registerUrl);
    return promise.promise;
  }

  accountManagement() {
    var accountUrl = this.createAccountUrl();
    if (typeof accountUrl !== 'undefined') {
      window.cordova.plugins.browsertab.openUrl(accountUrl);
      return Promise.resolve();
    } else {
      throw 'Not supported by the OIDC server';
    }
  }

  redirectUri(options?) {
    if (options && options.redirectUri) {
      return options.redirectUri;
    } else if (this.options?.redirectUri) {
      return this.options.redirectUri;
    } else {
      return 'http://localhost';
    }
  }
}
