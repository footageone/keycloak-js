import { CallbackStorage } from './callback-storage';

export class LocalStorage implements CallbackStorage {
  constructor() {
    localStorage.setItem('kc-test', 'test');
    localStorage.removeItem('kc-test');
  }

  protected clearExpired() {
    var time = new Date().getTime();
    for (var i = 0; i < localStorage.length; i++) {
      var key = localStorage.key(i);
      if (key && key.indexOf('kc-callback-') == 0) {
        var value = localStorage.getItem(key);
        if (value) {
          try {
            var expires = JSON.parse(value).expires;
            if (!expires || expires < time) {
              localStorage.removeItem(key);
            }
          } catch (err) {
            localStorage.removeItem(key);
          }
        }
      }
    }
  }

  get(state: any) {
    if (!state) {
      return;
    }

    var key = 'kc-callback-' + state;
    var value = localStorage.getItem(key);
    if (value) {
      localStorage.removeItem(key);
      value = JSON.parse(value);
    }

    this.clearExpired();
    return value;
  }

  add(state: any) {
    this.clearExpired();

    var key = 'kc-callback-' + state.state;
    state.expires = new Date().getTime() + 60 * 60 * 1000;
    localStorage.setItem(key, JSON.stringify(state));
  }
}
