function probe(targetUrl) {
  https.get(targetUrl, (res) => {
    res.resume();
  });
}
