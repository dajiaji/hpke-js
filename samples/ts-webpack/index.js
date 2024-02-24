

import * as app from './app'

const test = async () => {
  app.test()
}
// setup exports on window
window.test = {
  test
}
