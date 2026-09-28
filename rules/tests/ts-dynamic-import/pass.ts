async function load() {
  const m = await import("./plugin.js");
  return m;
}
