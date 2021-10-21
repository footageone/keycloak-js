export interface CallbackStorage {
  get(state: string): any;
  add(state: any): any;
}
