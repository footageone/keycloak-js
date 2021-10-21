export interface PromiseWrapper<R, E> {
  setSuccess: (result?: R) => void;
  setError: (result?: E) => void;
  promise: Promise<R>;
}

export function createPromise<R, E>(): PromiseWrapper<R, E> {
  // Need to create a native Promise which also preserves the
  // interface of the custom promise type previously used by the API
  var p: any;
  const promise = new Promise<R>((resolve, reject) => {
    p.resolve = resolve;
    p.reject = reject;
  });

  return {
    promise,
    setSuccess: (result?: R) => {
      p.resolve(result);
    },

    setError: (result?: E) => {
      p.reject(result);
    },
  };
}
