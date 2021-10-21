export function fileLoaded(xhr: XMLHttpRequest) {
  return (
    xhr.status == 0 && xhr.responseText && xhr.responseURL.startsWith('file:')
  );
}
