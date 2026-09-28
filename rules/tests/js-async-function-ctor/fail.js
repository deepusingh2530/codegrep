const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
const run = new AsyncFunction("a", userCode);
