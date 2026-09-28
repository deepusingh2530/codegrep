class SearchesController < ApplicationController
  def index
    Rails.logger.info("search: " + params[:q])
  end
end
