def load_tree(request):
    tree = etree.parse(request.files["xml"])
    return tree
