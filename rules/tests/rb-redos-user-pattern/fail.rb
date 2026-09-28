class SearchesController < ApplicationController
  def index
    re = Regexp.new(params[:pattern])
  end
end
