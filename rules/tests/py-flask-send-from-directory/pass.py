def download(filename):
    return send_from_directory(app.config["UPLOAD"], filename)
