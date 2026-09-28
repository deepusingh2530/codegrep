User.objects.filter(id=uid).update(**request.POST)
