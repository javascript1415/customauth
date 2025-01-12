from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
import threading

class SendEmailThread(threading.Thread):
    def __init__(self, email):  # Changed to accept email object only
        self.email = email
        threading.Thread.__init__(self)
    
    def run(self):
        try:
            self.email.send()
        except Exception as e:
            print(f"Failed to send email: {e}")

def send_activation_email(recipient_email, activation_url):
    subject = "Activate your account on " + settings.SITE_NAME
    from_email = 'no_reply@demomailtrap.com'
    to_email = [recipient_email]
    
    # Load the html
    html_content = render_to_string('account/activation_email.html', 
                                  {'activation_url': activation_url})
    text_content = strip_tags(html_content)
    
    email = EmailMultiAlternatives(subject, text_content, from_email, to_email)
    email.attach_alternative(html_content, 'text/html')
    
    # Create and start the thread
    email_thread = SendEmailThread(email)
    email_thread.start()

def send_reset_password_email(recipient_email, absolute_url):
    subject = "reset ur password  " + settings.SITE_NAME
    from_email = 'no_reply@demomailtrap.com'
    to_email = [recipient_email]
    
    # Load the html
    
    html_content = render_to_string('account/reset_password_email.html', 
                                  { 'reset_url': absolute_url,  # This should be the complete URL
        'site_name': settings.SITE_NAME})
    text_content = strip_tags(html_content)
    
    email = EmailMultiAlternatives(subject, text_content, from_email, to_email)
    email.attach_alternative(html_content, 'text/html')
    
    # Create and start the thread
    email_thread = SendEmailThread(email)
    email_thread.start()