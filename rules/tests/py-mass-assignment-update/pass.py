User.objects.filter(id=uid).update(last_login=now)
