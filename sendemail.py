from django.core.mail import send_mail
from django.conf import settings
import os
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "suissma_bot.settings")  # Replace with your actual settings module
django.setup()

# def send_test_email():
#     subject = "Test Email from Django"
#     message = "This is a test email to check if email functionality is working."
#     from_email = settings.DEFAULT_FROM_EMAIL   # Ensure this is set in settings.py
#     recipient_list = ["kaushalkunal.tws@gmail.com"]  # Replace with your test email

#     try:
#         sent = send_mail(subject, message, from_email, recipient_list)
#         return sent > 0  # Returns True if at least one email is sent
#     except Exception as e:
#         print(f"Email sending failed: {e}")
#         return False
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string

def send_html_email():
    try:
        subject = 'Email send'
        from_email = settings.EMAIL_HOST_USER 
        to = "kaushalkunal.tws@gmail.com"
        

        msg = EmailMultiAlternatives(subject, '', from_email, [to])
        # msg.attach_alternative(html_content, "text/html")
        msg.send(fail_silently=False)
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

send_html_email()