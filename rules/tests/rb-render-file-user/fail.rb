class PagesController < ApplicationController
  def show
    render file: params[:page]
  end
end
