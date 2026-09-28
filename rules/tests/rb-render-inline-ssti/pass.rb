class EmailsController < ApplicationController
  def preview
    render inline: @welcome_template
  end
end
