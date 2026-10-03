path = os.path.join(UPLOAD_DIR, os.path.basename(filename))
return send_file(path)
