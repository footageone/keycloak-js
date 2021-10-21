interface Window {
  universalLinks: {
    subscribe(key: string, callback: (event) => void);
    unsubscribe(key: string);
  };
}
