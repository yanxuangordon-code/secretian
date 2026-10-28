// Builds a single self-contained index.html (word list + fonts + logic + page).
// Usage: PASSKEY=yourpasskey node build.js
// The passkey itself is never written into index.html, only a one-way fingerprint of it.
const fs = require("fs");
const SW = require("./core.js");

const passkey = process.env.PASSKEY;
if (!passkey) throw new Error("Set the passkey first, e.g.  PASSKEY=yourpasskey node build.js");

const base = fs.readFileSync("node_modules/word-list/words.txt", "utf8").split("\n").filter(Boolean);
const extras = fs
  .readFileSync("extras.txt", "utf8")
  .split("\n")
  .filter((line) => !line.trim().startsWith("#"))
  .join(" ")
  .toLowerCase()
  .split(/[^a-z]+/)
  .filter(Boolean);

const words = Array.from(new Set(base.concat(extras))).sort();
if (!words.every((w) => /^[a-z]+$/.test(w))) throw new Error("word list has unexpected characters");

const font = (file) => fs.readFileSync("fonts/" + file).toString("base64");
const core = fs.readFileSync("core.js", "utf8");
const tpl = fs.readFileSync("template.html", "utf8");
const html = tpl
  .replace("/*FONT_DISPLAY*/", () => font("unbounded.woff2"))
  .replace("/*FONT_BODY*/", () => font("figtree.woff2"))
  .replace("/*CORE*/", () => core)
  .replace("/*GATE*/", () => SW.verifier(passkey))
  .replace("/*WORDS*/", () => words.join(" "));
fs.writeFileSync("index.html", html);
console.log("built index.html:", words.length, "words (" + new Set(extras).size + " extra),", (html.length / 1e6).toFixed(2), "MB");
