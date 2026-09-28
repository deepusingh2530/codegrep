class UploadsController < ApplicationController
  def create
    File.write(Rails.root.join("log", "events.log"), line)
  end
end
