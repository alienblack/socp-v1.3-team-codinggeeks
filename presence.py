online_users = set()

def user_online(username):
    online_users.add(username)

def user_offline(username):
    online_users.discard(username)

def is_user_online(username):
    return username in online_users
