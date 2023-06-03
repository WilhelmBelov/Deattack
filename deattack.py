#!/usr/bin/python3

import time
import socket
import queue
import threading as th
import Settings
import requests

global run
run = 1
url = 'http://91.201.54.215/api/v1.0/attacks/set/data'
cur_sec_time = lambda: int(round(time.time()))

def ids():
    global q1
    global sniff
    while 1:
        try:
            fm1 = sniff.recvfrom(6000)
            fm = bytearray(fm1[0])
            radio_tap_lenght = fm[2]
            if fm[radio_tap_lenght] == 192:
                print('fix packet attacks')
                bssid1 = fm[radio_tap_lenght + 4 + 6 + 6 : radio_tap_lenght + 4 + 6 + 6 + 6]
                bssid = ':'.join('%02x' % b for b in bssid1)
                q1.put(bssid)
        except OSError:
            break

def insert_frame():
    global q1
    global table
    global firstFixFlag
    table = []
    firstFixFlag = True
    while 1:
            mac = q1.get()
            try:
                if mac == None: raise ValueError
                # change cur_sec_time inside subarray if find mac in table
                sub_arr = next(x for x in table if x[0] == mac)
                new_sub_arr = (sub_arr[0], cur_sec_time(), sub_arr[2])
                table[table.index(sub_arr)] = new_sub_arr
            except StopIteration:
                print('add to table information about attacks')
                times = cur_sec_time()
                table.append((mac, times, times))
                if firstFixFlag:
                    datatime = time.ctime(times)
                    data = '"Datatime":"{0}", "Mac_dev":"{1}", "Duration":"-1", "Device":"{2}"'.format(datatime, mac, Settings.IP)
                    data = '[{' + data+ '}]'
                    print(data)
                    request_send(data)
                    firstFixFlag = False
    #            print(table)
            except ValueError:
                break

def request_send(send_data):
    try:
        r = requests.post(url, data=send_data, timeout=10)
        answer = r.text
        print(answer)
    except Exception as er:
        print(er)

def send_to_server():
    global table
    global run
    global firstFixFlag
    s1='{'
    s2='}'
    while 1:
        data = ''
        for elem in table:
            interval = cur_sec_time() - elem[1]
            if  interval > 90:
                Datatime = time.ctime(elem[2])
                Duration = cur_sec_time() - elem[2] - 90
                data = '{0},{1}"Datatime":"{2}", "Mac_dev":"{3}", "Duration":"{4}", "Device":"{5}"{6}'.format(data, s1, Datatime, elem[0], Duration, Settings.IP, s2)
                table.remove(elem)
        if len(data) > 0:
            send_data='[' + data[1:len(data)] + ']'
            print(send_data)
            request_send(send_data)
            firstFixFlag = True
        if run:
            time.sleep(1)
        else:
            break


def exit():
    global sniff
    global q1
    global run
    sniff.close()
    q1.put(None)
    run = 0

def start(wificard):
    global q1
    global table
    global sniff
    q1 = queue.Queue()
    table = []
    try:
        sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
        sniff.bind((wificard, 0x0003))
        print('Bind set for track attacks')
    except Exception as e:
        print(e)
    i = th.Thread(target = ids)
    f = th.Thread(target = insert_frame)
    s = th.Thread(target = send_to_server)
    i.start()
    f.start()
    s.start()

#Settings.IP = '10.0.5.142'
#start('wlan0mon')
