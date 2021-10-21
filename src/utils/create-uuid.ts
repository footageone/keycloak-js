import { generateRandomString } from './generate-random-string';

export function createUUID() {
  var hexDigits = '0123456789abcdef';
  var s: any = generateRandomString(36, hexDigits).split('');
  s[14] = '4';
  s[19] = hexDigits.substr((s[19] & 0x3) | 0x8, 1);
  s[8] = s[13] = s[18] = s[23] = '-';
  return s.join('');
}
