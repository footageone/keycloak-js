import { generateRandomString } from './generate-random-string';

export function generateCodeVerifier(len: number) {
  return generateRandomString(
    len,
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  );
}
