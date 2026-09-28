class FetchesController < ApplicationController
  def show
    resp = HTTParty.get(params[:url])
  end
end
