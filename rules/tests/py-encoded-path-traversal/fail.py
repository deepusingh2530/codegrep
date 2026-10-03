path = os.path.join(UPLOAD_DIR, urllib.parse.unquote(request.args["file"]))
return send_file(path)
