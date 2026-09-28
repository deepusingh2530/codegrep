def configure(app):
    app.conf.task_serializer = "json"
    app.conf.result_serializer = "json"
