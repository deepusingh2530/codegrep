func dial(addr string) error {
    conf := &ssh.ClientConfig{
        User:            "deploy",
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    }
    _, err := ssh.Dial("tcp", addr, conf)
    return err
}
