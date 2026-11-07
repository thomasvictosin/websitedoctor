import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const fixture = new URL("./fixtures/problematic-site/", import.meta.url);
const read = (name) => readFile(new URL(name, fixture), "utf8");

test("browser problem site contains reproducible accessibility, layout, runtime, and request failures", async () => {
  const [html, css, js] = await Promise.all([read("index.html"), read("style.css"), read("app.js")]);
  assert.match(css, /width:\s*1100px/); // horizontal overflow at mobile widths
  assert.match(css, /#mobile-nav\s*\{\s*display:\s*none/); // broken narrow-screen navigation
  assert.match(html, /<img\s+src=/i); // missing alt attribute
  assert.match(html, /<input\s+type="email"\s+placeholder=/i); // missing form label
  assert.match(css, /color:\s*#aaa;\s*background:\s*#fff/); // low contrast
  assert.match(js, /throw new Error/); // JavaScript exception
  assert.match(js, /fetch\("\/missing-api-endpoint"\)/); // failed network request
});
