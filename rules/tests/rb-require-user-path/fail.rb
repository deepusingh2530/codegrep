class PluginsController < ApplicationController
  def load_plugin
    require params[:plugin]
  end
end
