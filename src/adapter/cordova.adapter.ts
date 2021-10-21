import { AbstractKeycloak } from '../index';
import { createPromise } from '../create-promise';

var cordovaOpenWindowWrapper = (loginUrl, target, options) => {
  // @ts-ignore
  if (window.cordova && window.cordova.InAppBrowser) {
    // Use inappbrowser for IOS and Android if available
    // @ts-ignore
    return window.cordova.InAppBrowser.open(loginUrl, target, options);
  } else {
    return window.open(loginUrl, target, options);
  }
};

function shallowCloneCordovaOptions(userOptions): any {
  if (userOptions && userOptions.cordovaOptions) {
    return Object.keys(userOptions.cordovaOptions).reduce(function (
      options,
      optionName,
    ) {
      options[optionName] = userOptions.cordovaOptions[optionName];
      return options;
    },
    {});
  } else {
    return {};
  }
}

var formatCordovaOptions = function (cordovaOptions) {
  return Object.keys(cordovaOptions)
    .map((options, optionName) => {
      return `${optionName}=${cordovaOptions[optionName]}`;
    })
    .join(',');
};

var createCordovaOptions = function (userOptions) {
  var cordovaOptions = shallowCloneCordovaOptions(userOptions);
  cordovaOptions.location = 'no';
  if (userOptions && userOptions.prompt == 'none') {
    cordovaOptions.hidden = 'yes';
  }
  return formatCordovaOptions(cordovaOptions);
};

export class CordovaAdapter extends AbstractKeycloak {
  login(options) {
    var promise = createPromise();

    var cordovaOptions = createCordovaOptions(options);
    var loginUrl = this.createLoginUrl(options);
    var ref = cordovaOpenWindowWrapper(loginUrl, '_blank', cordovaOptions);
    var completed = false;

    var closed = false;
    var closeBrowser = function () {
      closed = true;
      ref.close();
    };

    ref.addEventListener('loadstart', (event) => {
      if (event.url.indexOf('http://localhost') == 0) {
        var callback = this.parseCallback(event.url);
        this.processCallback(callback, promise);
        closeBrowser();
        completed = true;
      }
    });

    ref.addEventListener('loaderror', (event) => {
      if (!completed) {
        if (event.url.indexOf('http://localhost') == 0) {
          var callback = this.parseCallback(event.url);
          this.processCallback(callback, promise);
          closeBrowser();
          completed = true;
        } else {
          promise.setError();
          closeBrowser();
        }
      }
    });

    ref.addEventListener('exit', (event) => {
      if (!closed) {
        promise.setError({
          reason: 'closed_by_user',
        });
      }
    });

    return Promise.resolve();
  }

  logout(options) {
    var promise = createPromise();
    var logoutUrl = this.createLogoutUrl(options);
    var ref = cordovaOpenWindowWrapper(
      logoutUrl,
      '_blank',
      'location=no,hidden=yes',
    );

    var error;

    ref.addEventListener('loadstart', function (event) {
      if (event.url.indexOf('http://localhost') == 0) {
        ref.close();
      }
    });

    ref.addEventListener('loaderror', function (event) {
      if (event.url.indexOf('http://localhost') == 0) {
        ref.close();
      } else {
        error = true;
        ref.close();
      }
    });

    ref.addEventListener('exit', (event) => {
      if (error) {
        promise.setError();
      } else {
        this.clearToken();
        promise.setSuccess();
      }
    });

    return Promise.resolve();
  }

  register(options) {
    var promise = createPromise();
    var registerUrl = this.createRegisterUrl(options);
    var cordovaOptions = createCordovaOptions(options);
    var ref = cordovaOpenWindowWrapper(registerUrl, '_blank', cordovaOptions);
    ref.addEventListener('loadstart', (event) => {
      if (event.url.indexOf('http://localhost') == 0) {
        ref.close();
        var oauth = this.parseCallback(event.url);
        this.processCallback(oauth, promise);
      }
    });
    return Promise.resolve();
  }

  accountManagement() {
    var accountUrl = this.createAccountUrl();
    if (typeof accountUrl !== 'undefined') {
      var ref = cordovaOpenWindowWrapper(accountUrl, '_blank', 'location=no');
      ref.addEventListener('loadstart', (event) => {
        if (event.url.indexOf('http://localhost') == 0) {
          ref.close();
        }
      });
      return Promise.resolve();
    } else {
      throw 'Not supported by the OIDC server';
    }
  }

  redirectUri() {
    return 'http://localhost';
  }
}
