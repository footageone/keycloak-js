export function getOrigin() {
  if (!window.location.origin) {
    return (
      window.location.protocol +
      '//' +
      window.location.hostname +
      (window.location.port ? ':' + window.location.port : '')
    );
  } else {
    return window.location.origin;
  }
}
