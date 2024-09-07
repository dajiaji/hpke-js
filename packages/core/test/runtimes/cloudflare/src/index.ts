import { testServer } from "./server.ts";

export default {
  async fetch(request, _env, _ctx): Promise<Response> {
    return await testServer(request);
  },
} satisfies ExportedHandler<Env>;
