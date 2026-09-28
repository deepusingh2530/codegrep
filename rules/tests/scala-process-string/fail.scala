def run(request: Request): Int = Process(request.queryString("cmd").head)!
