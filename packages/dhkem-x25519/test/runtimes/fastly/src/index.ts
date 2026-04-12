/// <reference types="@fastly/js-compute" />

import { testServer } from "./server";

addEventListener(
  "fetch",
  (event: FetchEvent) => event.respondWith(testServer(event.request)),
);
