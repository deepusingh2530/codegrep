public void handle(MultipartHttpServletRequest req) throws Exception {
  MultipartFile part = req.getFile("file");
  part.transferTo(new File(uploadDir, part.getOriginalFilename()));
}
