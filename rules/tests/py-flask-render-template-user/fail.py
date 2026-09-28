def view():
    return render_template(request.args.get("page"))
