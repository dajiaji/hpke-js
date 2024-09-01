const path = require("path");
module.exports = [{
  mode: "development",
  entry: "./index.js",
  watch: true,
  plugins: [],
  resolve: {
    alias: {
      "@hpke/core": path.resolve("./node_modules/@hpke/core"),
    },
    fallback: {
      "crypto": false,
    },
  },
}];
