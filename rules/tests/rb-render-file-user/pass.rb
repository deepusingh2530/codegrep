class PagesController < ApplicationController
  def show
    render file: Rails.root.join("public", "404.html")
  end
end
