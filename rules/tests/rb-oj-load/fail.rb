class EventsController < ApplicationController
  def create
    data = Oj.load(request.raw_post)
  end
end
