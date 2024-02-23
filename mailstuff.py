import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

"""Tested with via google smtp server"""
smtp_s,port = ("smtp.something.com", 465)
sender_mail = "example@something.com"
pw = "smtp_auth_pw"


def send_pw_reset(recipient,html_template):
    
    message = MIMEMultipart("alternative")
    message["Subject"] = "Breehze-Auth password reset"
    message["From"] = sender_mail
    message["To"] = recipient
    html_embed = MIMEText(html_template.decode("utf-8"),"html")
    message.attach(html_embed)
    try:
        with smtplib.SMTP_SSL(smtp_s,port) as server:
            server.login(sender_mail, pw)  
            server.sendmail(sender_mail, recipient, message.as_string())
            print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")