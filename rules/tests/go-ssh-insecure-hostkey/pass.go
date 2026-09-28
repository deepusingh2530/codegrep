func dial(addr string, peer ssh.PublicKey) error {
    conf := &ssh.ClientConfig{
        User:            "deploy",
        HostKeyCallback: ssh.FixedHostKey(peer),
    }
    _, err := ssh.Dial("tcp", addr, conf)
    return err
}
