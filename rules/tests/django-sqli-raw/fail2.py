qs = Model.objects.annotate(x=RawSQL(sql))
