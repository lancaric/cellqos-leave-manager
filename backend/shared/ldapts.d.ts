declare module "ldapts" {
  export class Client {
    constructor(options: { url: string; timeout?: number; connectTimeout?: number });
    bind(dn: string, password: string): Promise<void>;
    unbind(): Promise<void>;
    search(
      baseDN: string,
      options: {
        scope?: "base" | "one" | "sub";
        filter: string;
        attributes?: string[];
        sizeLimit?: number;
      }
    ): Promise<{ searchEntries: Array<Record<string, unknown>> }>;
  }
}
