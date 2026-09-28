func main() {
    c := cors.New(cors.Options{
        CheckOrigin: func(r *http.Request) bool {
            return r.Host == "example.com"
        },
    })
    _ = c
}
