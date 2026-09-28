class UploadsController < ApplicationController
  def create
    File.write(params[:path], params[:content])
  end
end
