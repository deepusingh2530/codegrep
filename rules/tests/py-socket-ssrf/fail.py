def dial(request):
    conn = socket.create_connection((request.args.get("host"), 443))
