def run(client):
    stdin, out, err = client.exec_command("uptime")
