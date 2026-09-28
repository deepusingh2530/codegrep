let handler (req : Request.t) =
  let resp = Client.get (Req.uri req) in
  Lwt.return resp
