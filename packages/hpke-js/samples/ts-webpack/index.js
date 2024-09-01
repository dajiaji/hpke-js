import * as app from "./app.js";

const test = async () => {
  app.test();
};
// setup exports on window
window.test = {
  test,
};
