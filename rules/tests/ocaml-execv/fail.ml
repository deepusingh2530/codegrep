let run cmd =
  Unix.execv "/bin/sh" [| "sh"; "-c"; cmd |]
