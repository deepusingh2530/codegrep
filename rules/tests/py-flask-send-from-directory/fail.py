def download():
    return send_from_directory(app.config["UPLOAD"], request.args.get("name"))
