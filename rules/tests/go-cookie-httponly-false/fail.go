func handler(w http.ResponseWriter, r *http.Request) {
    http.SetCookie(w, &http.Cookie{
        Name:     "prefs",
        Value:    v,
        HttpOnly: false,
    })
}
