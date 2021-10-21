export function decodeToken<T>(str: string): NonNullable<T> {
  str = str.split('.')[1];

  str = str.replace(/-/g, '+');
  str = str.replace(/_/g, '/');
  switch (str.length % 4) {
    case 0:
      break;
    case 2:
      str += '==';
      break;
    case 3:
      str += '=';
      break;
    default:
      throw 'Invalid token';
  }

  str = decodeURIComponent(escape(atob(str)));

  return JSON.parse(str);
}
