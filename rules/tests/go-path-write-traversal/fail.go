func upload(header *multipart.FileHeader) error {
    f, err := os.Create(header.Filename)
    if err != nil {
        return err
    }
    defer f.Close()
    return nil
}
