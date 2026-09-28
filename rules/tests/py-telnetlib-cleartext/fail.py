import telnetlib
tn = telnetlib.Telnet(host, 23)
tn.login(user, password)
