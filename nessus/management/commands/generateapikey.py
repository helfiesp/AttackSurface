from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

# Generates an API key for a user:
# python manage.py generateapikey USERNAME

class Command(BaseCommand):
    help = 'Generate an API key for a user'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='Username for the user')

    def handle(self, *args, **options):
        username = options['username']
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(f"User '{username}' does not exist."))
            return

        token, created = Token.objects.get_or_create(user=user)
        self.stdout.write(self.style.SUCCESS(f"API Key for user '{username}': {token.key}"))
