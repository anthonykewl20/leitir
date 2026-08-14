import type { Runnable } from "./base.ts";
import { Base, greet } from "./base.ts";

export class Child extends Base implements Runnable {
  async run(): Promise<void> {
    greet();
    new Base();
    throw new Base();
  }
}
