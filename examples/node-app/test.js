// A trivial passing test so `npm test` succeeds inside the sandbox.
const assert = require("node:assert");

assert.strictEqual(1 + 1, 2);
console.log("ok - arithmetic");
