ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id=#{id}")
