import { AbstractKeycloak } from '../index';
import { createPromise } from '../create-promise';

export class CordovaNativeAdapter extends AbstractKeycloak {
  login(options) {
    var promise = createPromise<void, any>();
    var loginUrl = this.createLoginUrl(options);

    window.universalLinks.subscribe('keycloak', (event) => {
      window.universalLinks.unsubscribe('keycloak');
      window.cordova.plugins.browsertab.close();
      var oauth = this.parseCallback(event.url);
      this.processCallback(oauth, promise);
    });

    window.cordova.plugins.browsertab.openUrl(loginUrl);
    return promise.promise;
  }

  logout(options) {
    var promise = createPromise<void, any>();
    var logoutUrl = this.createLogoutUrl(options);

    window.universalLinks.subscribe('keycloak', (event) => {
      window.universalLinks.unsubscribe('keycloak');
      window.cordova.plugins.browsertab.close();
      this.clearToken();
      promise.setSuccess();
    });

    window.cordova.plugins.browsertab.openUrl(logoutUrl);
    return promise.promise;
  }

  register(options) {
    var promise = createPromise<void, any>();
    var registerUrl = this.createRegisterUrl(options);
    window.universalLinks.subscribe('keycloak', (event) => {
      window.universalLinks.unsubscribe('keycloak');
      window.cordova.plugins.browsertab.close();
      var oauth = this.parseCallback(event.url);
      this.processCallback(oauth, promise);
    });
    window.cordova.plugins.browsertab.openUrl(registerUrl);
    return promise.promise;
  }

  accountManagement() {
    var accountUrl = this.createAccountUrl();
    if (typeof accountUrl !== 'undefined') {
      window.cordova.plugins.browsertab.openUrl(accountUrl);
    } else {
      throw 'Not supported by the OIDC server';
    }
    return Promise.resolve();
  }

  redirectUri(options) {
    if (options && options.redirectUri) {
      return options.redirectUri;
    } else if (this.redirectUri) {
      return this.redirectUri;
    } else {
      return 'http://localhost';
    }
  }
}
