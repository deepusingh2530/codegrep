def configure(app):
    app.conf.task_serializer = "pickle"
    app.conf.result_serializer = "json"
