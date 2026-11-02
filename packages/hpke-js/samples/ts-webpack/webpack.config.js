module.exports = [{
  mode: "development",
  entry: "./index.js",
  watch: true,
  plugins: [],
  resolve: {
    fallback: {
      "crypto": false,
    },
  },
}];
