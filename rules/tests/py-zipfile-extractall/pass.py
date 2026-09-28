import tarfile
with tarfile.open(path) as t:
    t.extractall(dest)
