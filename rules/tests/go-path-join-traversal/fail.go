func resolve(r *http.Request) string {
    return filepath.Join(baseDir, r.URL.Query().Get("path"))
}
