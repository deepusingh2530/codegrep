class TokensController < ApplicationController
  def show
    cipher = OpenSSL::Cipher.new("aes-256-ecb")
  end
end
