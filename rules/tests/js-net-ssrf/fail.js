const sock = net.connect(targetHost, onConnect);
const tlsSock = tls.connect({ host: targetHost });
