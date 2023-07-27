import { testServer } from "../../server.js";

export default {
  port: 3001,
  async fetch(request) {
    return await testServer(request);
  },
};
