from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from chatbot.models import SocialToken
from rest_framework.response import Response
import os
import requests
from dotenv import load_dotenv
import time
import base64
from urllib.parse import urlencode

load_dotenv()

class Command(BaseCommand):
    help = 'Refresh expiring social access tokens'

    def handle(self, *args, **options):
        while True:
            now = timezone.now()
            soon = now + timedelta(seconds=5)
            expiring_tokens = SocialToken.objects.filter(expires_at__lte=soon, refresh_token__isnull=False)
            client_id = os.getenv("TWITTER_CLIENT_ID")
            client_secret = os.getenv("TWITTER_CLIENT_SECRET")
            if not client_id or not client_secret:
                self.stdout.write(self.style.ERROR("Missing Twitter client ID or secret in environment."))
                return
            basic_auth = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
            for token in expiring_tokens:
                try:
                    token_url = "https://api.twitter.com/2/oauth2/token"
                    data = {
                    "grant_type":"refresh_token",
                    "refresh_token":token.refresh_token,
                    "client_id":client_id,
                    }
                    headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": f"Basic {basic_auth}"
                    }
                    response = requests.post(token_url, data=urlencode(data), headers=headers)
                    if response.status_code == 200:
                        token_data = response.json()
                        token.access_token = token_data.get("access_token")
                        token.refresh_token = token_data.get("refresh_token", token.refresh_token)
                        expires_in = token_data.get("expires_in")
                        if expires_in:
                            token.expires_at = timezone.now() + timedelta(seconds=expires_in)
                        token.save()
                        self.stdout.write(self.style.SUCCESS(f"Refreshed token for id={token.id}"))
                    else:
                        self.stdout.write(self.style.ERROR(f"Failed to refresh token for id={token.id}: {response.text}")) 
                except requests.RequestException as e:
                    self.stdout.write(self.style.ERROR(f"Network error for token id={token.id}: {str(e)}"))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"Unexpected error for token id={token.id}: {str(e)}"))
            time.sleep(60*110)