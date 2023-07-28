import { testServer } from "../../server.js";

export default {
  port: 3002,
  async fetch(request) {
    return await testServer(request);
  },
};
