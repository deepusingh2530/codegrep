def resolve(handler):
    fn = getattr(handler, "handle")
    return fn
