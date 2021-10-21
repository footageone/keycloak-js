import { generateRandomData } from "./generate-random-data";

export function generateRandomString(len: number, alphabet: string){
    var randomData = generateRandomData(len);
    var chars = new Array(len);
    for (var i = 0; i < len; i++) {
        chars[i] = alphabet.charCodeAt(randomData[i] % alphabet.length);
    }
    return String.fromCharCode.apply(null, chars);
}
