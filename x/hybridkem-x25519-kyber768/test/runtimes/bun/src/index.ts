import { testServer } from "./server.ts";

export default {
  port: 3006,
  async fetch(request: Request): Promise<Response> {
    return await testServer(request);
  },
};
