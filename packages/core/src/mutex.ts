export class Mutex {
  #locked: Promise<void> = Promise.resolve();

  async lock(): Promise<() => void> {
    let releaseLock!: () => void;
    const nextLock = new Promise<void>((resolve) => {
      releaseLock = resolve;
    });
    const previousLock = this.#locked;
    this.#locked = nextLock;
    await previousLock;
    return releaseLock;
  }
}
