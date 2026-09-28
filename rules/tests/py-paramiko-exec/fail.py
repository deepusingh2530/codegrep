def run(client, request):
    stdin, out, err = client.exec_command(request.form.get("cmd"))
