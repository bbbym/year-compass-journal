import { readFile, mkdir, writeFile, rm } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const html = await readFile(new URL("index.html", root), "utf8");
const template = await readFile(new URL("worker/index.template.js", root), "utf8");
const output = template.replace("__APP_HTML__", JSON.stringify(html));
const distServer = new URL("dist/server/", root);
await rm(distServer, { recursive: true, force: true });
await mkdir(distServer, { recursive: true });
await writeFile(new URL("index.js", distServer), output);
console.log("Built Cloudflare Worker with embedded Year Compass app");
