def load_plugin(request):
    lib = ctypes.CDLL(request.args["lib"])
    return lib
