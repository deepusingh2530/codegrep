func handler(w http.ResponseWriter, r *http.Request) {
    http.SetCookie(w, &http.Cookie{
        Name:  "session",
        Value: sid,
        Secure: false,
    })
}
