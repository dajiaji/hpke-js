import { testServer } from "./server.ts";

export default {
  async fetch(request: Request): Promise<Response> {
    return await testServer(request);
  },
};
