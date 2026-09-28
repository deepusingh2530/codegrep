public void Search() {
  var ds = new DirectorySearcher();
  ds.Filter = "(objectClass=person)";
}
