export function generateRandomData(len: number) {
  // use web crypto APIs if possible
  var array: any = null;
  var crypto = window.crypto || (window as any).msCrypto;
  if (crypto && crypto.getRandomValues && window.Uint8Array) {
    array = new Uint8Array(len);
    crypto.getRandomValues(array);
    return array;
  }

  // fallback to Math random
  array = new Array(len);
  for (var j = 0; j < array.length; j++) {
    array[j] = Math.floor(256 * Math.random());
  }
  return array;
}
