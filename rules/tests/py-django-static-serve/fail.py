urlpatterns = [re_path(r"^media/(?P<path>.*)$", django.views.static.serve)]
