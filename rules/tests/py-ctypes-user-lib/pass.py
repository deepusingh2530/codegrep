def load_libc():
    lib = ctypes.CDLL("libc.so.6")
    return lib
