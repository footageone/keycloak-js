import { LocalStorage } from './local-storage';
import { CookieStorage } from './cookie-storage';
import { CallbackStorage } from './callback-storage';

export function createCallbackStorage(): CallbackStorage {
  try {
    return new LocalStorage();
  } catch (err) {}

  return new CookieStorage();
}
