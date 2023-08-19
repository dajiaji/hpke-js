import { testServer } from "../../server.js";

export default {
  port: 3006,
  async fetch(request) {
    return await testServer(request);
  },
};
