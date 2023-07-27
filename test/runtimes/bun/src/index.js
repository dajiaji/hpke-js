import { testServer } from "../../server.js";

export default {
  port: 3000,
  async fetch(request) {
    return await testServer(request);
  },
};
