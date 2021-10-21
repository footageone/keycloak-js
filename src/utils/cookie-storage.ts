import { CallbackStorage } from './callback-storage';

export class CookieStorage implements CallbackStorage {
  get(state: string) {
    if (!state) {
      return;
    }

    var value = this.getCookie('kc-callback-' + state);
    this.setCookie(`kc-callback-${state}`, '', this.cookieExpiration(-100));
    if (value) {
      return JSON.parse(value);
    }
  }

  add(state: any) {
    this.setCookie(
      `kc-callback-${state.state}`,
      JSON.stringify(state),
      this.cookieExpiration(60),
    );
  }

  removeItem(key: string) {
    this.setCookie(key, '', this.cookieExpiration(-100));
  }

  protected cookieExpiration(minutes: number) {
    var exp = new Date();
    exp.setTime(exp.getTime() + minutes * 60 * 1000);
    return exp;
  }

  protected getCookie(key: string) {
    var name = `${key}=`;
    var ca = document.cookie.split(';');
    for (var i = 0; i < ca.length; i++) {
      var c = ca[i];
      while (c.charAt(0) == ' ') {
        c = c.substring(1);
      }
      if (c.indexOf(name) == 0) {
        return c.substring(name.length, c.length);
      }
    }
    return '';
  }

  protected setCookie(key: string, value: string, expirationDate: Date) {
    document.cookie = `${key}=${value}; expires=${expirationDate.toUTCString()}; `;
  }
}
