import { KeycloakAdapter } from '../adapter/interface';
import { AbstractKeycloak } from '../index';
import {
  KeycloakFlow,
  KeycloakOnLoad,
  KeycloakPkceMethod,
  KeycloakResponseMode,
} from '../interface';

export interface KeycloakInitOptions {
  /**
   * Adds a [cryptographic nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce)
   * to verify that the authentication response matches the request.
   * @default true
   */
  useNonce?: boolean;

  /**
   *
   * Allow usage of different types of adapters or a custom adapter to make Keycloak work in different environments.
   *
   * The following options are supported:
   * - `default` - Use default APIs that are available in browsers.
   * - `cordova` - Use a WebView in Cordova.
   * - `cordova-native` - Use Cordova native APIs, this is recommended over `cordova`.
   * - `capacitor` - Use Cordova InApp Browser
   * - `capacitor-native` - Use external browser
   *
   * It's also possible to pass in a custom adapter for the environment you are running Keycloak in. In order to do so extend the `KeycloakAdapter` interface and implement the methods that are defined there.
   *
   * For example:
   *
   * ```ts
   * import Keycloak, { KeycloakAdapter } from 'keycloak-js';
   *
   * // Implement the 'KeycloakAdapter' interface so that all required methods are guaranteed to be present.
   * const MyCustomAdapter: KeycloakAdapter = {
   * 	login(options) {
   * 		// Write your own implementation here.
   * 	}
   *
   * 	// The other methods go here...
   * };
   *
   * const keycloak = new Keycloak();
   *
   * keycloak.init({
   * 	adapter: MyCustomAdapter,
   * });
   * ```
   */
  adapter?:
    | 'default'
    | 'cordova'
    | 'cordova-native'
    | 'capacitor'
    | 'capacitor-native'
    | KeycloakAdapter;

  /**
   * Specifies an action to do on load.
   */
  onLoad?: KeycloakOnLoad;

  /**
   * Set an initial value for the token.
   */
  token?: string;

  /**
   * Set an initial value for the refresh token.
   */
  refreshToken?: string;

  /**
   * Set an initial value for the id token (only together with `token` or
   * `refreshToken`).
   */
  idToken?: string;

  /**
   * Set an initial value for skew between local time and Keycloak server in
   * seconds (only together with `token` or `refreshToken`).
   */
  timeSkew?: number;

  /**
   * Set to enable/disable monitoring login state.
   * @default true
   */
  checkLoginIframe?: boolean;

  /**
   * Set the interval to check login state (in seconds).
   * @default 5
   */
  checkLoginIframeInterval?: number;

  /**
   * Set the OpenID Connect response mode to send to Keycloak upon login.
   * @default fragment After successful authentication Keycloak will redirect
   *                   to JavaScript application with OpenID Connect parameters
   *                   added in URL fragment. This is generally safer and
   *                   recommended over query.
   */
  responseMode?: KeycloakResponseMode;

  /**
   * Specifies a default uri to redirect to after login or logout.
   * This is currently supported for adapter 'cordova-native' and 'default'
   */
  redirectUri?: string;

  /**
   * Specifies an uri to redirect to after silent check-sso.
   * Silent check-sso will only happen, when this redirect uri is given and
   * the specified uri is available whithin the application.
   */
  silentCheckSsoRedirectUri?: string;

  /**
   * Specifies whether the silent check-sso should fallback to "non-silent"
   * check-sso when 3rd party cookies are blocked by the browser. Defaults
   * to true.
   */
  silentCheckSsoFallback?: boolean;

  /**
   * Set the OpenID Connect flow.
   * @default standard
   */
  flow?: KeycloakFlow;

  /**
   * Configures the Proof Key for Code Exchange (PKCE) method to use.
   * The currently allowed method is 'S256'.
   * If not configured, PKCE will not be used.
   */
  pkceMethod?: KeycloakPkceMethod;

  /**
   * Enables logging messages from Keycloak to the console.
   * @default false
   */
  enableLogging?: boolean;

  /**
   * @undocumented
   */
  scope?: any;
}
