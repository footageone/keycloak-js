import { decodeToken } from './utils/decode-token';
import { KeycloakInitOptions } from './options/init-options';
import { createUUID } from './utils/create-uuid';
import { KeycloakAdapter, KeycloakInstance } from './adapter/interface';
import {
  KeycloakLoginOptions,
  KeycloakRegisterOptions,
} from './options/login-options';
import { KeycloakLogoutOptions } from './options/logout-options';
import { Endpoints } from './endpoints';
import { createPromise, PromiseWrapper } from './create-promise';
import { createCallbackStorage } from './utils/create-callback-storage';
import { CallbackStorage } from './utils/callback-storage';
import { fileLoaded } from './utils/file-loaded';
import { generatePkceChallenge } from './utils/generate-pkce-challenge';
import { generateCodeVerifier } from './utils/generate-code-verifier';
import { getOrigin } from './utils/get-origin';
import { KeycloakConfig } from './options/config';
import { KeycloakTokenParsed } from './token-parsed';
import {
  KeycloakError,
  KeycloakFlow,
  KeycloakProfile,
  KeycloakResponseType,
} from './interface';
import { KeycloakRoles } from './roles';
import { KeycloakResourceAccess } from './resource-access';

export async function keycloak(
  config: KeycloakConfig | string,
  adapter:
    | 'default'
    | 'cordova'
    | 'cordova-native'
    | 'capacitor'
    | 'capacitor-native'
    | KeycloakAdapter,
) {
  if (typeof adapter === 'string') {
    switch (adapter) {
      case 'capacitor':
        const { CapacitorAdapter } = await import(
          './adapter/capacitor.adapter'
        );
        return new CapacitorAdapter(config);
      case 'capacitor-native':
        const { CapacitorNativeAdapter } = await import(
          './adapter/capacitor-native.adapter'
        );
        return new CapacitorNativeAdapter(config);
      case 'cordova':
        const { CordovaAdapter } = await import('./adapter/cordova.adapter');
        return new CordovaAdapter(config);
      case 'cordova-native':
        const { CordovaNativeAdapter } = await import(
          './adapter/cordova-native.adapter'
        );
        return new CordovaNativeAdapter(config);
    }
  } else if (adapter != null) {
    return new adapter(config);
  } else {
    const { DefaultAdapter } = await import('./adapter/default.adapter');
    return new DefaultAdapter(config);
  }
}

export abstract class AbstractKeycloak implements KeycloakInstance {
  public onReady?: (authenticated?: boolean) => void;
  public onAuthSuccess?: () => void;
  public onAuthError?: (errorData?: KeycloakError) => void;
  public onAuthRefreshSuccess?: () => void;
  public onAuthRefreshError?: () => void;
  public onAuthLogout?: () => void;
  public onTokenExpired?: () => void;
  public onActionUpdate?: (status: 'success' | 'cancelled' | 'error') => void;

  public authenticated: boolean = false;
  public token?: string;
  public refreshToken?: string;
  protected endpoints?: Endpoints;
  protected useNonce?: boolean;
  protected loginIframe: any;
  public loginRequired?: boolean;
  public responseMode: any;
  public responseType?: KeycloakResponseType;
  public flow?: KeycloakFlow;
  public timeSkew?: number;
  public authServerUrl: any;
  public clientId: any;
  protected callbackStorage?: CallbackStorage;
  protected scope: any;
  protected pkceMethod: any;
  public sessionId: any;
  protected silentCheckSsoRedirectUri?: string | boolean;
  protected silentCheckSsoFallback?: boolean;
  protected enableLogging?: boolean;
  public tokenParsed?: KeycloakTokenParsed;
  public refreshTokenParsed?: KeycloakTokenParsed;
  public realm: any;
  public userInfo: any;
  protected tokenTimeoutHandle: any;
  public idToken: any;
  public idTokenParsed: NonNullable<any>;
  public subject: string | undefined;
  public realmAccess?: KeycloakRoles;
  public resourceAccess?: KeycloakResourceAccess;
  protected iframeVersion: any;
  protected options?: KeycloakInitOptions;
  protected logInfo: (...args: any) => void;
  protected logWarn: (...args: any) => void;
  protected refreshQueue: Array<PromiseWrapper<any, any>> = [];
  public clientSecret?: string;
  public profile?: KeycloakProfile;

  public abstract login(options?: KeycloakLoginOptions): Promise<void>;
  public abstract logout(options?: KeycloakLogoutOptions): Promise<void>;
  public abstract register(options?: KeycloakRegisterOptions): Promise<void>;
  public abstract accountManagement(): Promise<void>;
  public abstract redirectUri(options?: { redirectUri?: string }): string;

  constructor(protected config?: KeycloakConfig | string) {
    this.logInfo = this.createLogger(console.info);
    this.logWarn = this.createLogger(console.warn);
  }

  public init(options: KeycloakInitOptions) {
    this.options = options;
    this.authenticated = false;

    this.callbackStorage = createCallbackStorage();

    if (this.options) {
      if (typeof this.options.useNonce !== 'undefined') {
        this.useNonce = this.options.useNonce;
      }

      if (typeof this.options.checkLoginIframe !== 'undefined') {
        this.loginIframe.enable = this.options.checkLoginIframe;
      }

      if (this.options.checkLoginIframeInterval) {
        this.loginIframe.interval = this.options.checkLoginIframeInterval;
      }

      if (this.options.onLoad === 'login-required') {
        this.loginRequired = true;
      }

      if (this.options.responseMode) {
        if (
          this.options.responseMode === 'query' ||
          this.options.responseMode === 'fragment'
        ) {
          this.responseMode = this.options.responseMode;
        } else {
          throw 'Invalid value for responseMode';
        }
      }

      if (this.options.flow) {
        switch (this.options.flow) {
          case 'standard':
            this.responseType = 'code';
            break;
          case 'implicit':
            this.responseType = 'id_token token';
            break;
          case 'hybrid':
            this.responseType = 'code id_token token';
            break;
          default:
            throw 'Invalid value for flow';
        }
        this.flow = this.options.flow;
      }

      if (this.options.timeSkew != null) {
        this.timeSkew = this.options.timeSkew;
      }

      if (this.options.silentCheckSsoRedirectUri) {
        this.silentCheckSsoRedirectUri = this.options.silentCheckSsoRedirectUri;
      }

      if (typeof this.options.silentCheckSsoFallback === 'boolean') {
        this.silentCheckSsoFallback = this.options.silentCheckSsoFallback;
      } else {
        this.silentCheckSsoFallback = true;
      }

      if (this.options.pkceMethod) {
        if (this.options.pkceMethod !== 'S256') {
          throw 'Invalid value for pkceMethod';
        }
        this.pkceMethod = this.options.pkceMethod;
      }

      if (typeof this.options.enableLogging === 'boolean') {
        this.enableLogging = this.options.enableLogging;
      } else {
        this.enableLogging = false;
      }

      if (typeof this.options.scope === 'string') {
        this.scope = this.options.scope;
      }
    }

    var promise = createPromise<boolean, any>();

    var initPromise = createPromise();
    initPromise.promise
      .then(() => {
        this.onReady && this.onReady(this.authenticated);
        promise.setSuccess(this.authenticated);
      })
      .catch(function (errorData) {
        promise.setError(errorData);
      });

    var configPromise = this.loadConfig(this.config);

    const onLoad = () => {
      var options: any = {};
      var doLogin = (prompt) => {
        if (!prompt) {
          options.prompt = 'none';
        }

        this.login(options)
          .then(function () {
            initPromise.setSuccess();
          })
          .catch(function () {
            initPromise.setError();
          });
      };
      switch (this.options?.onLoad) {
        case 'check-sso':
          if (this.loginIframe.enable) {
            this.setupCheckLoginIframe().then(() => {
              this.checkLoginIframe()
                .then((unchanged) => {
                  if (!unchanged) {
                    this.silentCheckSsoRedirectUri
                      ? this.checkSsoSilently(initPromise)
                      : doLogin(false);
                  } else {
                    initPromise.setSuccess();
                  }
                })
                .catch(function () {
                  initPromise.setError();
                });
            });
          } else {
            this.silentCheckSsoRedirectUri
              ? this.checkSsoSilently(initPromise)
              : doLogin(false);
          }
          break;
        case 'login-required':
          doLogin(true);
          break;
        default:
          throw 'Invalid value for onLoad';
      }
    };

    const processInit = () => {
      var callback = this.parseCallback(window.location.href);

      if (callback) {
        window.history.replaceState(window.history.state, '', callback.newUrl);
      }

      if (callback && callback.valid) {
        return this.setupCheckLoginIframe()
          .then(() => {
            this.processCallback(callback, initPromise);
          })
          .catch((e) => {
            initPromise.setError();
          });
      } else if (this.options) {
        if (this.options.token && this.options.refreshToken) {
          this.#setToken(
            this.options.token,
            this.options.refreshToken,
            this.options.idToken,
          );

          if (this.loginIframe.enable) {
            this.setupCheckLoginIframe().then(() => {
              this.checkLoginIframe()
                .then((unchanged) => {
                  if (unchanged) {
                    this.onAuthSuccess && this.onAuthSuccess();
                    initPromise.setSuccess();
                    this.scheduleCheckIframe();
                  } else {
                    initPromise.setSuccess();
                  }
                })
                .catch(() => {
                  initPromise.setError();
                });
            });
          } else {
            this.updateToken(-1)
              .then(() => {
                this.onAuthSuccess && this.onAuthSuccess();
                initPromise.setSuccess();
              })
              .catch(() => {
                this.onAuthError && this.onAuthError();
                if (this.options?.onLoad) {
                  onLoad();
                } else {
                  initPromise.setError();
                }
              });
          }
        } else if (this.options.onLoad) {
          onLoad();
        } else {
          initPromise.setSuccess();
        }
      } else {
        initPromise.setSuccess();
      }
    };

    function domReady() {
      var promise = createPromise();

      var checkReadyState = function () {
        if (
          document.readyState === 'interactive' ||
          document.readyState === 'complete'
        ) {
          document.removeEventListener('readystatechange', checkReadyState);
          promise.setSuccess();
        }
      };
      document.addEventListener('readystatechange', checkReadyState);

      checkReadyState(); // just in case the event was already fired and we missed it (in case the init is done later than at the load time, i.e. it's done from code)

      return promise.promise;
    }

    configPromise.then(() => {
      domReady()
        .then(() => this.check3pCookiesSupported())
        .then(processInit)
        .catch(() => {
          promise.setError();
        });
    });
    configPromise.catch(function () {
      promise.setError();
    });
    return promise.promise;
  }

  public async loadUserInfo() {
    var url = this.endpoints?.userinfo();
    var req = new XMLHttpRequest();
    if (url) {
      const headers = new Headers({
        Accept: 'application/json',
        Authorization: `bearer ${this.token}`,
      });
      const response = await fetch(url, { headers });

      if (response.status === 200) {
        this.userInfo = await response.json();
        return this.userInfo;
      } else {
        throw response.status;
      }
    } else {
      return Promise.reject();
    }
  }

  clearToken() {
    if (this.token) {
      this.#setToken(null, null, null);
      this.onAuthLogout && this.onAuthLogout();
      if (this.loginRequired) {
        this.login();
      }
    }
  }

  isTokenExpired(minValidity) {
    if (!this.tokenParsed || (!this.refreshToken && this.flow != 'implicit')) {
      throw 'Not authenticated';
    }

    if (this.timeSkew == null) {
      this.logInfo(
        '[KEYCLOAK] Unable to determine if token is expired as timeskew is not set',
      );
      return true;
    }

    var expiresIn = this.tokenParsed?.exp
      ? this.tokenParsed.exp -
        Math.ceil(new Date().getTime() / 1000) +
        this.timeSkew
      : -1;

    if (minValidity) {
      if (isNaN(minValidity)) {
        throw 'Invalid minValidity';
      }
      expiresIn -= minValidity;
    }
    return expiresIn < 0;
  }

  public updateToken(minValidity) {
    var promise = createPromise<boolean, any>();

    if (!this.refreshToken) {
      promise.setError();
      return promise.promise;
    }

    minValidity = minValidity || 5;

    var exec = () => {
      var refreshToken = false;
      if (minValidity == -1) {
        refreshToken = true;
        this.logInfo('[KEYCLOAK] Refreshing token: forced refresh');
      } else if (!this.tokenParsed || this.isTokenExpired(minValidity)) {
        refreshToken = true;
        this.logInfo('[KEYCLOAK] Refreshing token: token expired');
      }

      if (!refreshToken) {
        promise.setSuccess(false);
      } else {
        var params =
          'grant_type=refresh_token&' + 'refresh_token=' + this.refreshToken;
        var url = this.endpoints?.token();

        this.refreshQueue.push(promise);

        if (this.refreshQueue.length == 1 && url != null) {
          var req = new XMLHttpRequest();
          req.open('POST', url, true);
          req.setRequestHeader(
            'Content-type',
            'application/x-www-form-urlencoded',
          );
          req.withCredentials = true;

          params += `&client_id=${encodeURIComponent(this.clientId)}`;

          var timeLocal = new Date().getTime();

          req.onreadystatechange = () => {
            if (req.readyState == 4) {
              if (req.status == 200) {
                this.logInfo('[KEYCLOAK] Token refreshed');

                timeLocal = (timeLocal + new Date().getTime()) / 2;

                var tokenResponse = JSON.parse(req.responseText);

                this.#setToken(
                  tokenResponse['access_token'],
                  tokenResponse['refresh_token'],
                  tokenResponse['id_token'],
                  timeLocal,
                );

                this.onAuthRefreshSuccess && this.onAuthRefreshSuccess();
                for (
                  var p = this.refreshQueue.pop();
                  p != null;
                  p = this.refreshQueue.pop()
                ) {
                  p.setSuccess(true);
                }
              } else {
                this.logWarn('[KEYCLOAK] Failed to refresh token');

                if (req.status == 400) {
                  this.clearToken();
                }

                this.onAuthRefreshError && this.onAuthRefreshError();
                for (
                  var p = this.refreshQueue.pop();
                  p != null;
                  p = this.refreshQueue.pop()
                ) {
                  p.setError(true);
                }
              }
            }
          };

          req.send(params);
        }
      }
    };

    if (this.loginIframe.enable) {
      var iframePromise = this.checkLoginIframe();
      iframePromise
        .then(function () {
          exec();
        })
        .catch(function () {
          promise.setError();
        });
    } else {
      exec();
    }

    return promise.promise;
  }

  #setToken(token, refreshToken, idToken, timeLocal?) {
    if (this.tokenTimeoutHandle) {
      clearTimeout(this.tokenTimeoutHandle);
      this.tokenTimeoutHandle = null;
    }

    if (refreshToken) {
      this.refreshToken = refreshToken;
      this.refreshTokenParsed = decodeToken(refreshToken);
    } else {
      delete this.refreshToken;
      delete this.refreshTokenParsed;
    }

    if (idToken) {
      this.idToken = idToken;
      this.idTokenParsed = decodeToken(idToken);
    } else {
      delete this.idToken;
      delete this.idTokenParsed;
    }

    if (token) {
      this.token = token;
      this.tokenParsed = decodeToken(token);
      this.sessionId = this.tokenParsed.session_state;
      this.authenticated = true;
      this.subject = this.tokenParsed.sub;
      this.realmAccess = this.tokenParsed.realm_access;
      this.resourceAccess = this.tokenParsed.resource_access;

      if (timeLocal && this.tokenParsed.iat) {
        this.timeSkew = Math.floor(timeLocal / 1000) - this.tokenParsed.iat;
      }

      if (this.timeSkew != null) {
        this.logInfo(
          `[KEYCLOAK] Estimated time difference between browser and server is ${this.timeSkew} seconds`,
        );

        if (this.onTokenExpired && this.tokenParsed.exp) {
          var expiresIn =
            (this.tokenParsed.exp -
              new Date().getTime() / 1000 +
              this.timeSkew) *
            1000;
          this.logInfo(
            '[KEYCLOAK] Token expires in ' +
              Math.round(expiresIn / 1000) +
              ' s',
          );
          if (expiresIn <= 0) {
            this.onTokenExpired();
          } else {
            this.tokenTimeoutHandle = setTimeout(
              this.onTokenExpired,
              expiresIn,
            );
          }
        }
      }
    } else {
      delete this.token;
      delete this.tokenParsed;
      delete this.subject;
      delete this.realmAccess;
      delete this.resourceAccess;

      this.authenticated = false;
    }
  }

  #getRealmUrl() {
    if (typeof this.authServerUrl !== 'undefined') {
      if (this.authServerUrl.charAt(this.authServerUrl.length - 1) == '/') {
        return `${this.authServerUrl}realms/${encodeURIComponent(this.realm)}`;
      } else {
        return `${this.authServerUrl}/realms/${encodeURIComponent(this.realm)}`;
      }
    } else {
      return undefined;
    }
  }

  #setupOidcEndoints(oidcConfiguration) {
    if (!oidcConfiguration) {
      this.endpoints = {
        authorize: () => {
          return `${this.#getRealmUrl()}/protocol/openid-connect/auth`;
        },
        token: () => {
          return `${this.#getRealmUrl()}/protocol/openid-connect/token`;
        },
        logout: () => {
          return `${this.#getRealmUrl()}/protocol/openid-connect/logout`;
        },
        checkSessionIframe: () => {
          var src = `${this.#getRealmUrl()}/protocol/openid-connect/login-status-iframe.html`;
          if (this.iframeVersion) {
            src = `${src}?version=${this.iframeVersion}`;
          }
          return src;
        },
        thirdPartyCookiesIframe: () => {
          var src = `${this.#getRealmUrl()}/protocol/openid-connect/3p-cookies/step1.html`;
          if (this.iframeVersion) {
            src = `${src}?version=${this.iframeVersion}`;
          }
          return src;
        },
        register: () => {
          return `${this.#getRealmUrl()}/protocol/openid-connect/registrations`;
        },
        userinfo: () => {
          return `${this.#getRealmUrl()}/protocol/openid-connect/userinfo`;
        },
      };
    } else {
      this.endpoints = {
        authorize: function () {
          return oidcConfiguration.authorization_endpoint;
        },
        token: function () {
          return oidcConfiguration.token_endpoint;
        },
        logout: function () {
          if (!oidcConfiguration.end_session_endpoint) {
            throw 'Not supported by the OIDC server';
          }
          return oidcConfiguration.end_session_endpoint;
        },
        checkSessionIframe: function () {
          if (!oidcConfiguration.check_session_iframe) {
            throw 'Not supported by the OIDC server';
          }
          return oidcConfiguration.check_session_iframe;
        },
        register: function () {
          throw 'Redirection to "Register user" page not supported in standard OIDC mode';
        },
        userinfo: function () {
          if (!oidcConfiguration.userinfo_endpoint) {
            throw 'Not supported by the OIDC server';
          }
          return oidcConfiguration.userinfo_endpoint;
        },
      };
    }
  }

  createLoginUrl(options) {
    var state = createUUID();
    var nonce = createUUID();

    var redirectUri = this.redirectUri(options);

    // @todo interface
    var callbackState: any = {
      state: state,
      nonce: nonce,
      redirectUri: encodeURIComponent(redirectUri),
    };

    if (options && options.prompt) {
      callbackState.prompt = options.prompt;
    }

    var baseUrl;
    if (options && options.action == 'register') {
      baseUrl = this.endpoints?.register();
    } else {
      baseUrl = this.endpoints?.authorize();
    }

    var scope = (options && options.scope) || this.scope;
    if (!scope) {
      // if scope is not set, default to "openid"
      scope = 'openid';
    } else if (scope.indexOf('openid') === -1) {
      // if openid scope is missing, prefix the given scopes with it
      scope = `openid ${scope}`;
    }

    var url = `${baseUrl}?client_id=${encodeURIComponent(
      this.clientId,
    )}&redirect_uri=${encodeURIComponent(
      redirectUri,
    )}&state=${encodeURIComponent(state)}&response_mode=${encodeURIComponent(
      this.responseMode,
    )}&response_type=${encodeURIComponent(
      // @ts-ignore
      this.responseType,
    )}&scope=${encodeURIComponent(scope)}`;
    if (this.useNonce) {
      url += `&nonce=${encodeURIComponent(nonce)}`;
    }

    if (options && options.prompt) {
      url += `&prompt=${encodeURIComponent(options.prompt)}`;
    }

    if (options && options.maxAge) {
      url += `&max_age=${encodeURIComponent(options.maxAge)}`;
    }

    if (options && options.loginHint) {
      url += `&login_hint=${encodeURIComponent(options.loginHint)}`;
    }

    if (options && options.idpHint) {
      url += `&kc_idp_hint=${encodeURIComponent(options.idpHint)}`;
    }

    if (options && options.action && options.action != 'register') {
      url += `&kc_action=${encodeURIComponent(options.action)}`;
    }

    if (options && options.locale) {
      url += `&ui_locales=${encodeURIComponent(options.locale)}`;
    }

    if (this.pkceMethod) {
      var codeVerifier = generateCodeVerifier(96);
      callbackState.pkceCodeVerifier = codeVerifier;
      var pkceChallenge = generatePkceChallenge(this.pkceMethod, codeVerifier);
      url += `&code_challenge=${pkceChallenge}`;
      url += `&code_challenge_method=${this.pkceMethod}`;
    }

    this.callbackStorage?.add(callbackState);

    return url;
  }

  createLogoutUrl(options) {
    return `${this.endpoints?.logout()}?redirect_uri=${encodeURIComponent(
      this.redirectUri(options),
    )}`;
  }

  createRegisterUrl(options) {
    if (!options) {
      options = {};
    }
    options.action = 'register';
    return this.createLoginUrl(options);
  }

  createAccountUrl(options?: KeycloakRegisterOptions) {
    var realm = this.#getRealmUrl();
    var url;
    if (typeof realm !== 'undefined') {
      url = `${realm}/account?referrer=${encodeURIComponent(
        this.clientId,
      )}&referrer_uri=${encodeURIComponent(this.redirectUri(options))}`;
      return url;
    }
  }

  protected processCallback(oauth, promise) {
    var code = oauth.code;
    var error = oauth.error;
    var prompt = oauth.prompt;

    var timeLocal = new Date().getTime();

    const authSuccess = (
      accessToken,
      refreshToken,
      idToken,
      fulfillPromise,
    ) => {
      timeLocal = (timeLocal + new Date().getTime()) / 2;

      this.#setToken(accessToken, refreshToken, idToken, timeLocal);

      if (
        this.useNonce &&
        ((this.tokenParsed && this.tokenParsed.nonce != oauth.storedNonce) ||
          (this.refreshTokenParsed &&
            this.refreshTokenParsed.nonce != oauth.storedNonce) ||
          (this.idTokenParsed && this.idTokenParsed.nonce != oauth.storedNonce))
      ) {
        this.logInfo('[KEYCLOAK] Invalid nonce, clearing token');
        this.clearToken();
        promise && promise.setError();
      } else {
        if (fulfillPromise) {
          this.onAuthSuccess && this.onAuthSuccess();
          promise && promise.setSuccess();
        }
      }
    };

    if (oauth['kc_action_status']) {
      this.onActionUpdate && this.onActionUpdate(oauth['kc_action_status']);
    }

    if (error) {
      if (prompt != 'none') {
        var errorData = {
          error: error,
          error_description: oauth.error_description,
        };
        this.onAuthError && this.onAuthError(errorData);
        promise && promise.setError(errorData);
      } else {
        promise && promise.setSuccess();
      }
      return;
    } else if (
      this.flow != 'standard' &&
      (oauth.access_token || oauth.id_token)
    ) {
      authSuccess(oauth.access_token, null, oauth.id_token, true);
    }

    if (this.flow != 'implicit' && code) {
      var params = 'code=' + code + '&grant_type=authorization_code';
      var url = this.endpoints?.token();

      if (url) {
        var req = new XMLHttpRequest();
        req.open('POST', url, true);
        req.setRequestHeader(
          'Content-type',
          'application/x-www-form-urlencoded',
        );

        params += `&client_id=${encodeURIComponent(this.clientId)}`;
        params += `&redirect_uri=${oauth.redirectUri}`;

        if (oauth.pkceCodeVerifier) {
          params += `&code_verifier=${oauth.pkceCodeVerifier}`;
        }

        req.withCredentials = true;

        req.onreadystatechange = () => {
          if (req.readyState == 4) {
            if (req.status == 200) {
              var tokenResponse = JSON.parse(req.responseText);
              authSuccess(
                tokenResponse['access_token'],
                tokenResponse['refresh_token'],
                tokenResponse['id_token'],
                this.flow === 'standard',
              );
              this.scheduleCheckIframe();
            } else {
              this.onAuthError && this.onAuthError();
              promise && promise.setError();
            }
          }
        };
        req.send(params);
      }
    }
  }

  protected parseCallback(url) {
    var oauth = this.parseCallbackUrl(url);
    if (!oauth) {
      return;
    }

    var oauthState = this.callbackStorage?.get(oauth.state);

    if (oauthState) {
      oauth.valid = true;
      oauth.redirectUri = oauthState.redirectUri;
      oauth.storedNonce = oauthState.nonce;
      oauth.prompt = oauthState.prompt;
      oauth.pkceCodeVerifier = oauthState.pkceCodeVerifier;
    }

    return oauth;
  }

  protected parseCallbackUrl(url: string) {
    var supportedParams: Array<string> = [];
    switch (this.flow) {
      case 'standard':
        supportedParams = [
          'code',
          'state',
          'session_state',
          'kc_action_status',
        ];
        break;
      case 'implicit':
        supportedParams = [
          'access_token',
          'token_type',
          'id_token',
          'state',
          'session_state',
          'expires_in',
          'kc_action_status',
        ];
        break;
      case 'hybrid':
        supportedParams = [
          'access_token',
          'token_type',
          'id_token',
          'code',
          'state',
          'session_state',
          'expires_in',
          'kc_action_status',
        ];
        break;
    }

    supportedParams.push('error');
    supportedParams.push('error_description');
    supportedParams.push('error_uri');

    var queryIndex = url.indexOf('?');
    var fragmentIndex = url.indexOf('#');

    var newUrl: any;
    var parsed: any;

    if (this.responseMode === 'query' && queryIndex !== -1) {
      newUrl = url.substring(0, queryIndex);
      parsed = this.parseCallbackParams(
        url.substring(
          queryIndex + 1,
          fragmentIndex !== -1 ? fragmentIndex : url.length,
        ),
        supportedParams,
      );
      if (parsed.paramsString !== '') {
        newUrl += '?' + parsed.paramsString;
      }
      if (fragmentIndex !== -1) {
        newUrl += url.substring(fragmentIndex);
      }
    } else if (this.responseMode === 'fragment' && fragmentIndex !== -1) {
      newUrl = url.substring(0, fragmentIndex);
      parsed = this.parseCallbackParams(
        url.substring(fragmentIndex + 1),
        supportedParams,
      );
      if (parsed.paramsString !== '') {
        newUrl += '#' + parsed.paramsString;
      }
    }

    if (parsed && parsed.oauthParams) {
      if (this.flow === 'standard' || this.flow === 'hybrid') {
        if (
          (parsed.oauthParams.code || parsed.oauthParams.error) &&
          parsed.oauthParams.state
        ) {
          parsed.oauthParams.newUrl = newUrl;
          return parsed.oauthParams;
        }
      } else if (this.flow === 'implicit') {
        if (
          (parsed.oauthParams.access_token || parsed.oauthParams.error) &&
          parsed.oauthParams.state
        ) {
          parsed.oauthParams.newUrl = newUrl;
          return parsed.oauthParams;
        }
      }
    }
  }

  protected loadConfig(url) {
    var promise = createPromise();
    var configUrl: string;

    if (this.config == null) {
      configUrl = 'keycloak.json';
      return this.loadConfigFromUrl(configUrl, promise);
    } else if (typeof this.config === 'string') {
      configUrl = this.config;
      return this.loadConfigFromUrl(configUrl, promise);
    } else {
      if (!this.config.clientId) {
        throw 'clientId missing';
      }

      this.clientId = this.config.clientId;

      var oidcProvider = this.config['oidcProvider'];
      if (!oidcProvider) {
        if (!this.config['url']) {
          var scripts = document.getElementsByTagName('script');
          for (var i = 0; i < scripts.length; i++) {
            if (scripts[i].src.match(/.*keycloak\.js/)) {
              this.config.url = scripts[i].src.substr(
                0,
                scripts[i].src.indexOf('/js/keycloak.js'),
              );
              break;
            }
          }
        }
        if (!this.config.realm) {
          throw 'realm missing';
        }

        this.authServerUrl = this.config.url;
        this.realm = this.config.realm;
        this.#setupOidcEndoints(null);
        promise.setSuccess();
      } else {
        if (typeof oidcProvider === 'string') {
          var oidcProviderConfigUrl;
          if (oidcProvider.charAt(oidcProvider.length - 1) == '/') {
            oidcProviderConfigUrl = `${oidcProvider}.well-known/openid-configuration`;
          } else {
            oidcProviderConfigUrl = `${oidcProvider}/.well-known/openid-configuration`;
          }
          var req = new XMLHttpRequest();
          req.open('GET', oidcProviderConfigUrl, true);
          req.setRequestHeader('Accept', 'application/json');

          req.onreadystatechange = () => {
            if (req.readyState == 4) {
              if (req.status == 200 || fileLoaded(req)) {
                var oidcProviderConfig = JSON.parse(req.responseText);
                this.#setupOidcEndoints(oidcProviderConfig);
                promise.setSuccess();
              } else {
                promise.setError();
              }
            }
          };

          req.send();
        } else {
          this.#setupOidcEndoints(oidcProvider);
          promise.setSuccess();
        }
      }
      return promise.promise;
    }
  }

  private loadConfigFromUrl(configUrl: string, promise) {
    var req = new XMLHttpRequest();
    req.open('GET', configUrl, true);
    req.setRequestHeader('Accept', 'application/json');

    req.onreadystatechange = () => {
      if (req.readyState == 4) {
        if (req.status == 200 || fileLoaded(req)) {
          var config = JSON.parse(req.responseText);

          this.authServerUrl = config['auth-server-url'];
          this.realm = config['realm'];
          this.clientId = config['resource'];
          this.#setupOidcEndoints(null);
          promise.setSuccess();
        } else {
          promise.setError();
        }
      }
    };

    req.send();
    return promise.promise;
  }

  protected parseCallbackParams(paramsString, supportedParams) {
    var p = paramsString.split('&');
    var result = {
      paramsString: '',
      oauthParams: {},
    };
    for (var i = 0; i < p.length; i++) {
      var split = p[i].indexOf('=');
      var key = p[i].slice(0, split);
      if (supportedParams.indexOf(key) !== -1) {
        result.oauthParams[key] = p[i].slice(split + 1);
      } else {
        if (result.paramsString !== '') {
          result.paramsString += '&';
        }
        result.paramsString += p[i];
      }
    }
    return result;
  }

  protected setupCheckLoginIframe() {
    var promise = createPromise();

    if (!this.loginIframe.enable) {
      promise.setSuccess();
      return promise.promise;
    }

    if (this.loginIframe.iframe) {
      promise.setSuccess();
      return promise.promise;
    }

    var iframe = document.createElement('iframe');
    this.loginIframe.iframe = iframe;

    iframe.onload = () => {
      var authUrl = this.endpoints?.authorize();
      if (authUrl?.charAt(0) === '/') {
        this.loginIframe.iframeOrigin = getOrigin();
      } else {
        this.loginIframe.iframeOrigin = authUrl?.substring(
          0,
          authUrl.indexOf('/', 8),
        );
      }
      promise.setSuccess();
    };

    var src = this.endpoints?.checkSessionIframe();
    if (src) {
      iframe.setAttribute('src', src);
      iframe.setAttribute('title', 'keycloak-session-iframe');
      iframe.style.display = 'none';
      document.body.appendChild(iframe);
    }

    var messageCallback = (event) => {
      if (
        event.origin !== this.loginIframe.iframeOrigin ||
        this.loginIframe.iframe.contentWindow !== event.source
      ) {
        return;
      }

      if (
        !(
          event.data == 'unchanged' ||
          event.data == 'changed' ||
          event.data == 'error'
        )
      ) {
        return;
      }

      if (event.data != 'unchanged') {
        this.clearToken();
      }

      var callbacks = this.loginIframe.callbackList.splice(
        0,
        this.loginIframe.callbackList.length,
      );

      for (var i = callbacks.length - 1; i >= 0; --i) {
        var promise = callbacks[i];
        if (event.data == 'error') {
          promise.setError();
        } else {
          promise.setSuccess(event.data == 'unchanged');
        }
      }
    };

    window.addEventListener('message', messageCallback, false);

    return promise.promise;
  }

  protected scheduleCheckIframe() {
    if (this.loginIframe.enable) {
      if (this.token) {
        setTimeout(() => {
          this.checkLoginIframe().then((unchanged) => {
            if (unchanged) {
              this.scheduleCheckIframe();
            }
          });
        }, this.loginIframe.interval * 1000);
      }
    }
  }

  protected checkLoginIframe() {
    var promise = createPromise();

    if (this.loginIframe.iframe && this.loginIframe.iframeOrigin) {
      var msg = `${this.clientId} ${this.sessionId ? this.sessionId : ''}`;
      this.loginIframe.callbackList.push(promise);
      var origin = this.loginIframe.iframeOrigin;
      if (this.loginIframe.callbackList.length == 1) {
        this.loginIframe.iframe.contentWindow.postMessage(msg, origin);
      }
    } else {
      promise.setSuccess();
    }

    return promise.promise;
  }

  checkSsoSilently(initPromise) {
    var ifrm = document.createElement('iframe');
    var src = this.createLoginUrl({
      prompt: 'none',
      redirectUri: this.silentCheckSsoRedirectUri,
    });
    ifrm.setAttribute('src', src);
    ifrm.setAttribute('title', 'keycloak-silent-check-sso');
    ifrm.style.display = 'none';
    document.body.appendChild(ifrm);

    var messageCallback = (event) => {
      if (
        event.origin !== window.location.origin ||
        ifrm.contentWindow !== event.source
      ) {
        return;
      }

      var oauth = this.parseCallback(event.data);
      this.processCallback(oauth, initPromise);

      document.body.removeChild(ifrm);
      window.removeEventListener('message', messageCallback);
    };

    window.addEventListener('message', messageCallback);
  }

  protected check3pCookiesSupported() {
    var promise = createPromise();

    if (this.loginIframe.enable || this.silentCheckSsoRedirectUri) {
      var iframe = document.createElement('iframe');
      if (typeof this.endpoints?.thirdPartyCookiesIframe === 'function') {
        iframe.setAttribute('src', this.endpoints.thirdPartyCookiesIframe());
      }
      iframe.setAttribute('title', 'keycloak-3p-check-iframe');
      iframe.style.display = 'none';
      document.body.appendChild(iframe);

      var messageCallback = (event) => {
        if (iframe.contentWindow !== event.source) {
          return;
        }

        if (event.data !== 'supported' && event.data !== 'unsupported') {
          return;
        } else if (event.data === 'unsupported') {
          this.loginIframe.enable = false;
          if (this.silentCheckSsoFallback) {
            this.silentCheckSsoRedirectUri = false;
          }
          this.logWarn(
            "[KEYCLOAK] 3rd party cookies aren't supported by this browser. checkLoginIframe and " +
              'silent check-sso are not available.',
          );
        }

        document.body.removeChild(iframe);
        window.removeEventListener('message', messageCallback);
        promise.setSuccess();
      };

      window.addEventListener('message', messageCallback, false);
    } else {
      promise.setSuccess();
    }

    return promise.promise;
  }

  createLogger(fn: Function) {
    return () => {
      if (this.enableLogging) {
        fn.apply(console, Array.prototype.slice.call(arguments));
      }
    };
  }

  public hasRealmRole(role: string): boolean {
    var access = this.realmAccess;
    return !!access && access.roles.includes(role);
  }

  public hasResourceRole(role: string, resource?: string): boolean {
    if (!this.resourceAccess) {
      return false;
    }

    var access = this.resourceAccess[resource || this.clientId];
    return !!access && access.roles.includes(role);
  }

  public async loadUserProfile(): Promise<KeycloakProfile | undefined> {
    var url = `${this.#getRealmUrl()}/account`;
    var req = new XMLHttpRequest();
    req.open('GET', url, true);
    req.setRequestHeader('Accept', 'application/json');
    req.setRequestHeader('Authorization', `bearer ${this.token}`);

    const response = await fetch(url, { headers: this.headers() });
    if (response.status === 200) {
      this.profile = await response.json();
      return this.profile;
    } else {
      throw response;
    }
  }

  protected headers() {
    return new Headers({
      Accept: 'application/json',
      Authorization: `bearer ${this.token}`,
    });
  }
}
