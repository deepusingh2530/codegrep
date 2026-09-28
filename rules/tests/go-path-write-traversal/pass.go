func upload(fixedName string) error {
    f, err := os.Create(fixedName)
    if err != nil {
        return err
    }
    defer f.Close()
    return nil
}
