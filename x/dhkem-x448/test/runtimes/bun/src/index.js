import { testServer } from "../../server.js";

export default {
  port: 3004,
  async fetch(request) {
    return await testServer(request);
  },
};
