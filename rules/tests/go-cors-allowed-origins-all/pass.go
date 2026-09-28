func main() {
    c := cors.New(cors.Options{
        AllowedOrigins: []string{"https://example.com"},
    })
    _ = c
}
