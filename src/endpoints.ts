export interface Endpoints {
  logout: () => string;
  checkSessionIframe: () => string;
  authorize: () => string;
  thirdPartyCookiesIframe?: () => string;
  userinfo: () => string;
  token: () => string;
  register: () => string;
}
