func files(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "files/"+r.URL.Path)
}
