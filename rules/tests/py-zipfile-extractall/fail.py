import zipfile
with zipfile.ZipFile(path) as z:
    z.extractall(dest)
