function probe(targetUrl) {
  return fetchData(targetUrl).then(process);
}
