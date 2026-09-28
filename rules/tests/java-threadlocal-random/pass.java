SecureRandom sr = new SecureRandom();
byte[] token = new byte[32];
sr.nextBytes(token);
