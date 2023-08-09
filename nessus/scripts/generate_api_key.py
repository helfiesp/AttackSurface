from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

username = 'christian'

user, created = User.objects.get_or_create(username=username)
token, created = Token.objects.get_or_create(user=user)

print(f"API Token for {user.username}: {token.key}")