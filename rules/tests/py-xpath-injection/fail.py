def search(request, root):
    el = root.xpath(request.args["expr"])
    return el
