func main() {
    c := cors.New(cors.Options{
        AllowedOrigins: []string{"*"},
    })
    _ = c
}
