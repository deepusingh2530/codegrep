class FetchesController < ApplicationController
  def show
    resp = HTTParty.get("https://api.example.com/status")
  end
end
