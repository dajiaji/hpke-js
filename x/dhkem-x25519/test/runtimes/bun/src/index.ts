import { testServer } from "./server.ts";

export default {
  port: 3003,
  async fetch(request: Request): Promise<Response> {
    return await testServer(request);
  },
};
