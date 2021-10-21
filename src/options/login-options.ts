export interface KeycloakLoginOptions {
    /**
     * Specifies the scope parameter for the login url
     * The scope 'openid' will be added to the scope if it is missing or undefined.
     */
    scope?: string;

    /**
     * Specifies the uri to redirect to after login.
     */
    redirectUri?: string;

    /**
     * By default the login screen is displayed if the user is not logged into
     * Keycloak. To only authenticate to the application if the user is already
     * logged in and not display the login page if the user is not logged in, set
     * this option to `'none'`. To always require re-authentication and ignore
     * SSO, set this option to `'login'`.
     */
    prompt?: 'none'|'login';

    /**
     * If value is `'register'` then user is redirected to registration page,
     * otherwise to login page.
     */
    action?: string;

    /**
     * Used just if user is already authenticated. Specifies maximum time since
     * the authentication of user happened. If user is already authenticated for
     * longer time than `'maxAge'`, the SSO is ignored and he will need to
     * authenticate again.
     */
    maxAge?: number;

    /**
     * Used to pre-fill the username/email field on the login form.
     */
    loginHint?: string;

    /**
     * Used to tell Keycloak which IDP the user wants to authenticate with.
     */
    idpHint?: string;

    /**
     * Sets the 'ui_locales' query param in compliance with section 3.1.2.1
     * of the OIDC 1.0 specification.
     */
    locale?: string;

    /**
     * Specifies arguments that are passed to the Cordova in-app-browser (if applicable).
     * Options 'hidden' and 'location' are not affected by these arguments.
     * All available options are defined at https://cordova.apache.org/docs/en/latest/reference/cordova-plugin-inappbrowser/.
     * Example of use: { zoom: "no", hardwareback: "yes" }
     */
    cordovaOptions?: { [optionName: string]: string };
}

export type KeycloakRegisterOptions = Omit<KeycloakLoginOptions, 'action'>;
