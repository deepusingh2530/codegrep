public void Upload(HttpPostedFile fu) {
  fu.PostedFile.SaveAs(uploadDir + fu.FileName);
}
