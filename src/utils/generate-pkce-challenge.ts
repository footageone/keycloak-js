import { sha256 } from 'js-sha256';
import base64js from 'base64-js';

export function generatePkceChallenge(
  pkceMethod: string,
  codeVerifier: string,
) {
  switch (pkceMethod) {
    // The use of the "plain" method is considered insecure and therefore not supported.
    case 'S256':
      // hash codeVerifier, then encode as url-safe base64 without padding
      var hashBytes = new Uint8Array(sha256.arrayBuffer(codeVerifier));
      return base64js
        .fromByteArray(hashBytes)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/\=/g, '');
    default:
      throw 'Invalid value for pkceMethod';
  }
}
