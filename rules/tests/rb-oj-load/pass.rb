class EventsController < ApplicationController
  def create
    payload = Oj.dump(event)
  end
end
