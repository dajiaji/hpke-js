import { testServer } from "../../server.js";

export default {
  port: 3005,
  async fetch(request) {
    return await testServer(request);
  },
};
