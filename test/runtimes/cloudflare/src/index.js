import { testServer } from "../../server.js";

export default {
  async fetch(request) {
    return await testServer(request);
  },
};
