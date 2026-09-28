class EmailsController < ApplicationController
  def preview
    render inline: params[:template]
  end
end
