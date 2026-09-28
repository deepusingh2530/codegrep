func handler(w http.ResponseWriter, r *http.Request) {
    log.Printf("search: %s", r.URL.Query().Get("q"))
}
