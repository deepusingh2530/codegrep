public void Save(string data) {
  File.WriteAllText(logPath, data);
}
