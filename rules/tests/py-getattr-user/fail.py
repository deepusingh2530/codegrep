def resolve(request, handler):
    fn = getattr(handler, request.args["method"])
    return fn
