class SearchesController < ApplicationController
  def index
    re = Regexp.new("\\A[a-z]+\\z")
  end
end
