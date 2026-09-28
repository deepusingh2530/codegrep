users = User.ransack(params.permit(:name, :email))
