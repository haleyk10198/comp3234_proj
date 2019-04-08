#!/usr/bin/python3

# Student name and No.: Kwok Kin Hei (3035371587)
# Student name and No.: Tse Tsz Hei (3035344479)
# Development platform: Ubuntu Linux, Mac OS
# Python version: 3.7
# Version:


# Stage 1 check list:
# do_User()
# do_List()
# do_Join()
# do_Poke()

from tkinter import *
import sys
import socket
import threading
import time
from functools import reduce


#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address),
# and str(Port) to form a string that be the input
# to this hash function
#


def sdbm_hash(instr):
    hash_value = 0
    for c in instr:
        hash_value = int(ord(c)) + (hash_value << 6) + (hash_value << 16) - hash_value
    return hash_value & 0xffffffffffffffff


class User:
    def __init__(self, name='', addr='0', port='0'):
        self.name = name
        self.addr = addr
        self.port = port
        self.msgID = -1
        self.fwd = False
        self.bwd = False
        self.fwd_bwd_semaphore = threading.Semaphore(1)
        self.sck = None
        # List of poke timestamps(ts)
        self.poke_ts = []

    def recv_ACK(self):
        # receive ACK and remove the oldest poke ts
        self.get_poke_ts().pop(0)
        CmdWin.insert(1.0, "\nReceived ACK from {}".format(self.get_name()))

    def send_poke(self):
        # Sends a poke message to this user and add a timestamp
        global poke_sck, me, chatroom_name
        poke_sck.sendto("K:{}:{}::\r\n".format(chatroom_name, me.get_name()).encode('utf-8'),
                        (self.get_addr(), int(self.get_port())))
        CmdWin.insert(1.0, "\nHave sent a poke to {}".format(self.get_name()))
        ts = time.time()
        self.get_poke_ts().append(ts)
        print("[debug] Pending poke ts {}".format(self.get_poke_ts()))
        thread = threading.Thread(target=self.monitor_poke)
        thread.setDaemon(True)
        thread.start()

    def monitor_poke(self):
        # monitor if the ACK is well received
        time.sleep(2)
        print("[debug] Monitor poke thread has woke")
        print("[debug] Current time is {}, the time stamps are {}".format(time.time(), self.get_poke_ts()))
        if self.get_poke_ts() and time.time() - self.get_poke_ts()[0] > 2.0:
            # if there are unresolved pokes and it has been >2.0sec since the oldest poke
            CmdWin.insert(1.0, "\nFailed to receive poke from {}".format(self.get_name()))
            # give up on receiving the ACK
            self.get_poke_ts().pop(0)

    def get_socket(self):
        return self.sck

    def set_socket(self, sck):
        self.sck = sck

    def get_msgID(self):
        return self.msgID

    def set_msgID(self, msgID):
        print("[debug] Setting {}'s msgID from {} to {}".format(self.get_name(), self.msgID, msgID))
        if self.msgID == -1 or self.msgID + 1 == msgID:
            self.msgID = msgID
            print("[debug] msgID updated successfully.")
            return True

        print("[debug] Failed to update msgID.")
        return False

    @property
    def hash(self):
        return sdbm_hash(self.name + self.addr + self.port)

    def set_name(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def set_addr(self, addr):
        self.addr = addr

    def get_addr(self):
        return self.addr

    def set_port(self, port):
        self.port = port

    def get_port(self):
        return self.port

    def get_poke_ts(self):
        return self.poke_ts

    def declare_bwd(self, sck):

        global CONNECTED

        self.fwd_bwd_semaphore.acquire()

        # This is irreversible
        if not self.fwd:
            self.bwd = True  # target self
            self.sck = sck

        bwd = self.bwd

        print("[debug] Tried to build backward link w/ {}, status: {}"
              .format(self.name, "Success" if bwd else "Failed"))
        self.fwd_bwd_semaphore.release()

        if bwd:
            if not CONNECTED:
                CmdWin.insert(1.0, "\nYou are now connected to the chatroom.")
            CONNECTED = True
            listen_message(self)

        return bwd

    def declare_fwd(self, sck):

        global CONNECTED

        self.fwd_bwd_semaphore.acquire()

        # This is irreversible
        if not self.bwd:
            self.fwd = True  # at most one
            self.sck = sck

        fwd = self.fwd
        print("[debug] Tried to build forward link w/ {}, status: {}"
              .format(self.name, "Success" if fwd else "Failed"))

        if fwd:
            CmdWin.insert(1.0, "\nYou are now connected to the chatroom.")
            CONNECTED = True
            listen_message(self)

        self.fwd_bwd_semaphore.release()

        return fwd

    def is_fwd(self):
        return self.fwd

    def is_bwd(self):
        return self.bwd


class UserList:

    def __init__(self):
        self.lock = threading.Semaphore(1)
        self.users = []
        self.fwd_count = 0  # at most one
        self.hash = -1

    def get_user_from_addr(self, addr, port):
        for user in self.users:
            if user.get_addr() == str(addr) and user.get_port() == str(port):
                return user
        return None

    def get_names(self):
        # returns the list of username
        return [user.name for user in self.users]

    def add_user(self, user):
        if user.hash not in [u.hash for u in self.users]:
            if user is not me:
                CmdWin.insert(1.0, "\n{} @ ({}, {}) has joined the chatroom!"
                              .format(user.get_name(), user.get_addr(), user.get_port()))
            self.users.append(user)

    def remove(self, user):
        if user.sck:
            user.sck.close()
        self.users.remove(user)

    def acquire_lock(self):
        self.lock.acquire()

    def release_lock(self):
        self.lock.release()

    @property
    def length(self):
        return len(self.users)

    def get_element(self, i):
        return self.users[i]

    def declare_fwd(self, i, sck):  # at most one, return once success or fail
        if self.fwd_count == 0:
            if self.users[i].declare_fwd(sck):
                self.fwd_count += 1
                return True
        return False

    @property
    def bwd_count(self):
        return reduce(lambda cnt, user: cnt + user.is_bwd(), self.users)

    def get_hash(self):
        return self.hash

    def set_hash(self, hash):
        self.hash = hash

    def index(self, u):
        for i in range(0, len(self.users)):
            if self.users[i].hash == u.hash:
                return i

        return -1

    def get_user(self, u):
        for user in self.users:
            if user.hash == u.hash:
                return user

        return None

    def get_user_from_name(self, name):
        for user in self.users:
            if user.name == name:
                return user
        return None

    def get_user_from_hash(self, hash):
        for user in self.users:
            if user.hash == hash:
                return user

        return None

    @property
    def fwd_users(self):
        return list(filter(lambda x: x.is_fwd(), self.users))

    @property
    def bwd_users(self):
        return list(filter(lambda x: x.is_bwd(), self.users))


#
# Global variables
#

# me: self
me = User()
# chat room name joined
chatroom_name = ''
# fwd socket, moved to user
# peer_fwd_sck = socket.socket()
# bwd socket
bwd_sck = socket.socket()
# server socket
server_sck = socket.socket()
# holding users
user_list = UserList()
# bwd socket list
peer_bwd_socket_list = list()
# message id list
# msg_id_hid_list = list()

# Assume max no of bwd peers is 5
MAX_BACKWARD_LINKS = 5

CONNECTED = False

poke_sck = None

ACK_MESSAGE = "A::\r\n"


def UDP_listener():
    # Listener for UDP (poke) socket

    global ACK_MESSAGE, user_list, poke_sck

    while True:
        data, addr = poke_sck.recvfrom(1024)
        msg = data.decode('utf-8')

        print("[debug] Received {} from {}".format(msg, addr))

        if len(msg) == 0:
            setup_UDP()
        elif msg[0] == 'K':
            # if poke comes in
            instr = parse_semicolon_list(msg)

            roomname, username = instr
            if roomname != chatroom_name:
                print("[debug] Received invalid poke message, \"{}\"".format(instr))
            else:
                user = user_list.get_user_from_name(username)
                MsgWin.insert(1.0, "\n~~~[{}]Poke~~~".format(user.get_name()))
                print("[debug] Have sent out ACK message")
                poke_sck.sendto(ACK_MESSAGE.encode('utf-8'), (user.get_addr(), int(user.get_port())))

        elif msg == ACK_MESSAGE:
            # if ACK comes in
            print("\nReceived ACK from {}".format(addr))
            user = user_list.get_user_from_addr(addr[0], addr[1])
            user.recv_ACK()
        else:
            # ignore
            pass


def setup_UDP():
    # setup the poke port

    global poke_sck

    poke_sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    poke_sck.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    poke_sck.bind(('localhost', int(me.get_port())))
    me.set_addr(poke_sck.getsockname()[0])

    thread = threading.Thread(target=UDP_listener)
    thread.setDaemon(True)
    thread.start()


# randomly triggered by server, if not exist, add user. if exist, do nothing. return void
def update_members(instr):
    global user_list

    # Locking user list during updates
    user_list.acquire_lock()
    for i in range(0, len(instr), 3):
        user_list.add_user(User(instr[i], instr[i + 1], instr[i + 2]))
    user_list.release_lock()


# look the function below, return void
def reconnect_server():
    CmdWin.insert(1.0, '\nConnection lost! attempting to reconnect ...')
    connect_server()


# literally connect server, return void
def connect_server():
    try:
        server_sck.connect((sys.argv[1], int(sys.argv[2])))
    except socket.error as err:
        print("Cannot connect to room server at '{}:{}'".format(sys.argv[1], sys.argv[2]))
        print('Error message: ', err)
        sys.exit(0)


# check for socket connection status, True or False
def is_connected(sck):
    try:
        sck.getpeername()
        return True
    except socket.error:
        return False


def bwd_listener():
    global bwd_sck, user_list

    bwd_sck.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bwd_sck.bind(('localhost', int(me.get_port())))
    bwd_sck.listen(MAX_BACKWARD_LINKS)

    while True:
        bwd_client_socket, addr = bwd_sck.accept()
        print("[debug] Received some request to establish handshake")
        thread = threading.Thread(target=bwd_handler, args=(bwd_client_socket, addr))
        thread.setDaemon(True)
        thread.start()


def bwd_handler(bwd_client_socket, addr):
    global chatroom_name, user_list

    message = bwd_client_socket.recv(1000)

    # P:roomname:username:IP:Port:msgID::\r\n
    #      0        1      2  3    4
    message_contents = parse_semicolon_list(message.decode('utf-8'))
    user = user_list.get_user(User(message_contents[1], message_contents[2], message_contents[3]))
    print("[debug] Received a handshaking request from {}".format(addr))

    # For updating the chatroom member list
    try_join(chatroom_name)

    # Check if user exists in list
    if not user:
        bwd_client_socket.close()
        return

    if not user.declare_bwd(bwd_client_socket):
        bwd_client_socket.close()
        return
    else:
        # Handshaking procedures -----------------------------

        # Print out bwd msg to command window
        CmdWin.insert(1.0, "\n{} @ {} is now connected as your peer".format(message_contents[1], addr))

        # Add this new bwd new user to socket_list
        # peer_bwd_socket_list.append(bwd_client_socket)
        # This is moved inside declare bwd

        # Set new msgID by increment 1
        me.set_msgID(me.get_msgID() + 1)
        handshake_msg = "S:" + str(me.get_msgID()) + "::\r\n"
        bwd_client_socket.sendall(handshake_msg.encode('utf-8'))


# when self just join chat room, check for suitable fwd, then connect it
#   Condition, fwd != bwd, otherwise, the graph is corrupted
# If failed, do it again after 10 seconds and again and again if fail again
# If successful, break the infinite loop and exit the function
# return void
#
#
def select_peer():
    global user_list, me, chatroom_name

    while True:

        user_list.acquire_lock()
        my_id = user_list.index(me)

        for delta in range(1, user_list.length):
            start = (my_id + delta) % user_list.length
            peer = user_list.get_element(start)

            print("[debug] Engaging with {}".format(peer.name))

            if peer.bwd:

                print("[debug] Already formed backward link w/ {}, cannot build forward link".format(peer.name))
                continue

            else:

                try:

                    peer_fwd_sck = socket.socket()
                    peer_fwd_sck.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    peer_fwd_sck.connect((peer.addr, int(peer.port)))
                    peer_fwd_sck.sendall("P:{}:{}:{}:{}:{}::\r\n".format(
                        chatroom_name, me.get_name(), me.get_addr(), me.get_port(), me.get_msgID()
                    ).encode('utf-8'))

                    print("[debug] Sent out handshaking message")
                    return_msg = peer_fwd_sck.recv(1000).decode('utf-8')

                    if len(return_msg) == 0:
                        print("[debug] Failed to receive handshaking message")
                        peer_fwd_sck.close()
                        continue
                    else:
                        print("[debug] Received handshaking message")
                        peer.set_msgID(int(parse_semicolon_list(return_msg)[0]))
                        if user_list.declare_fwd(start, peer_fwd_sck):
                            user_list.release_lock()
                            break

                except socket.error as e:
                    print("[debug] Encountered socket error in select_peer!")
                    print(e)
                    continue
        else:
            user_list.release_lock()
            time.sleep(10)
            continue
        break


#
# Functions to handle user input
#


def validate_name(name):
    # validates user input names (eg: chatroom name, username)

    # rejects:
    # empty name
    # name with ':'

    if len(name) == 0:
        return False
    if name.find(':') != -1:
        return False

    return True


# Get name input and set it as username and clear the input box if valid
# If invalid, reject
#
def do_User():
    # Must be executed to set username before joining any group
    # This function is only available before any successful joins

    global me

    input_str = userentry.get()

    # insert check join condition here

    if not validate_name(input_str):
        outstr = "\n\'{}\' is an invalid username!".format(input_str)
    else:
        outstr = "\n[User] username: " + input_str
        me.set_name(input_str)
        userentry.delete(0, END)

    CmdWin.insert(1.0, outstr)


# Use it after you have handled the first character, it returns list
# it contains the message content, without the semicolon, the first character and the \r\n
def parse_semicolon_list(msg):
    # parse a ':' separated message into a list
    chatroom_list = msg.split(':')[1:-2]
    return chatroom_list


# Show all chat room
#
#
def do_List():
    global server_sck

    CmdWin.insert(1.0, "\nPress List")

    server_sck.sendall('L::\r\n'.encode('utf-8'))
    return_msg = server_sck.recv(1000).decode('utf-8')

    if len(return_msg) == 0:
        reconnect_server()
        return
    elif return_msg[0] == 'F':
        output_str = '\nEncountered error:\n' + return_msg.split(':')[1]
    else:
        chatroom_list = parse_semicolon_list(return_msg)

        if len(chatroom_list) == 0:
            output_str = '\nNo active chatrooms'
        else:
            output_str = '\nHere are the active chatrooms:'
            for chatroom in chatroom_list:
                output_str += '\n\t' + chatroom

    CmdWin.insert(1.0, output_str)


# Try to join a chat room
# return True if success, False if failed
def try_join(roomname):
    global me

    server_sck.sendall(
        "J:{}:{}:{}:{}::\r\n".format(roomname, me.get_name(), me.get_addr(), me.get_port()).encode('utf-8'))
    return_msg = server_sck.recv(1000).decode('utf-8')

    if len(return_msg) == 0:
        reconnect_server()
        return False
    elif return_msg[0] == 'F':
        CmdWin.insert(1.0, '\nEncountered error:\n' + return_msg.split(':')[1])
        return False
    else:
        CmdWin.insert(1.0, '\nReceived membership ACK from server')
        info_list = parse_semicolon_list(return_msg[1:-1])
        user_list.set_hash(int(info_list[0]))
        update_members(info_list[1:])
        return True


# Keep reporting to server for living
def keep_alive():
    global chatroom_name

    while True:
        print("Maintaining chatroom membership with server...")
        try_join(chatroom_name)

        time.sleep(20)


def do_Join():
    global user_list, chatroom_name, me, CONNECTED

    CmdWin.insert(1.0, "\nPress JOIN")
    output_str = ''

    if not me.get_name():
        CmdWin.insert(1.0, '\nPlease input your username first!')
        return

    if chatroom_name:
        CmdWin.insert(1.0, '\nYou have already joined a chatroom!')
        return

    if not is_connected(server_sck):
        connect_server()

    # get input string
    input_str = userentry.get()
    if not validate_name(input_str):
        output_str = "\n\'{}\' is an invalid chatroom name!".format(input_str)
    else:
        userentry.delete(0, END)
        if try_join(input_str):
            chatroom_name = input_str
            output_str = "\nYou have successfully joined the chatroom \'{}\'!".format(chatroom_name)
            output_str += "\nList of members:"

            for i in range(0, user_list.length):
                output_str += "\n\t{}".format(user_list.get_element(i).get_name())

            # setup thread for executing keepalive
            keep_alive_thread = threading.Thread(target=keep_alive)
            keep_alive_thread.setDaemon(True)
            keep_alive_thread.start()

            # setup peer network
            select_peer_thread = threading.Thread(target=select_peer)
            select_peer_thread.setDaemon(True)
            select_peer_thread.start()

            # handle bwd links
            bwd_listener_thread = threading.Thread(target=bwd_listener)
            bwd_listener_thread.setDaemon(True)
            bwd_listener_thread.start()

            # handle messages
            # message_listener_thread = threading.Thread(target=listen_message)
            # message_listener_thread.setDaemon(True)
            # message_listener_thread.start()

    CmdWin.insert(1.0, output_str)


def is_msg_valid(msg_list):
    origin_user = user_list.get_user_from_name(msg_list[2])
    if msg_list[0] != chatroom_name:
        return False

    if not origin_user:
        print("[debug] Received message from {} which is not recognized by user list, updating user list ..."
              .format(msg_list[2]))
        try_join(chatroom_name)
        origin_user = user_list.get_user_from_name(msg_list[2])
        if not origin_user:
            print("[debug] Unexpected error, failed to find user in the updated list.")
            return False
        else:
            print("[debug] Successfully found user in the updated list.")

    if str(origin_user.hash) != msg_list[1]:
        print("[debug] Unexpected error, user hash does not match the supplied hash.")
        print("[debug] Expected hash is {}, found {}".format(origin_user.hash, msg_list[1]))
        print("[debug] User detail: {}, {}, {}".format(origin_user.addr, origin_user.port, origin_user.name))
        return False
    if len(msg_list[5]) != int(msg_list[4]):
        print("[debug] Unexpected error, the length of message does not message the specified length")
        return False

    return origin_user.set_msgID(int(msg_list[3]))


def parse_msg_list(msg):
    msg_list = parse_semicolon_list(msg)
    for i in range(6, len(msg_list)):
        msg_list[5] += ":" + msg_list[i]

    return msg_list[0: 6]


def msg_listener(peer):
    while (True):
        # assuming text content is less than 500 bytes. 550 bytes are used for giving more spaces
        # CmdWin.insert(1.0, "Listening to msg")
        msg = peer.sck.recv(550).decode('utf-8')
        if len(msg) == 0:
            # remove the connection
            user_list.remove(peer)
        elif msg[0] != 'T':
            continue
        # T:    roomname:originHID:origin_username:msgID:msgLength:Message content::\r\n
        msg_list = parse_msg_list(msg)
        if is_msg_valid(msg_list):
            for each_user in user_list.fwd_users + user_list.bwd_users:
                each_user.get_socket().send(
                    msg.encode('utf-8')
                )

            count = 0
            start_index = 0
            for i in range(len(msg)):
                if msg[i] == ':':
                    count = count + 1
                    if count == 6:
                        start_index = i + 1
                        break

            MsgWin.insert(1.0,
                          "\nPeer: " + msg_list[2] + " msg: " + msg[start_index: start_index + int(msg_list[4])])  # change to length determined text
            # msg_id_hid_list.append(msgID)


def listen_message(peer):
    # for each peer, listen messages and send them to parse message function
    # and then send if needed or show it on screen only

    # Changed to listen to the passed peer only
    # This function is called by declare_fwd, declare_bwd

    peer_msg_listener_thread = threading.Thread(target=msg_listener, args=(peer,))
    peer_msg_listener_thread.setDaemon(True)
    peer_msg_listener_thread.start()


def do_Send():

    # get input string
    text_str = userentry.get()
    if text_str == '':
        CmdWin.insert(1.0, "\nPlease enter text.")
        return
    if not CONNECTED:
        CmdWin.insert(1.0, "\nPlease wait until you are properly connected with other peers")
        return
    userentry.delete(0, END)
    # send the message to all bwd links and the only fwd link
    msgID = me.get_msgID()
    # msg_id_hid_list.append(msgID)
    length_of_text = str(len(text_str))
    send_string = 'T:' + chatroom_name
    send_string = send_string + ':' + str(me.hash)
    send_string = send_string + ':' + me.get_name()
    send_string = send_string + ':' + str(msgID + 1)
    send_string = send_string + ':' + length_of_text
    send_string = send_string + ':' + text_str + '::\r\n'

    print(send_string)

    msg_list = parse_msg_list(send_string)
    if is_msg_valid(msg_list):
        for each_user in user_list.fwd_users + user_list.bwd_users:
            each_user.get_socket().send(
                send_string.encode('utf-8')
            )

        MsgWin.insert(1.0, "\nyourself: " + text_str)
        # T:roomname:originHID:origin_username:msgID:msgLength:Message content::\r\n
    else:
        print("[debug] Unexpected error, sending message is not valid.")
        print(msg_list)


def do_Poke():
    CmdWin.insert(1.0, "\nPress Poke")

    if not chatroom_name:
        # if hasn't joined a chatroom
        CmdWin.insert(1.0, "\nYou haven't joined a chatroom yet!")
        return

    if not CONNECTED:
        # if joined, but haven't got a link yet
        CmdWin.insert(1.0, "\nPlease wait until your client is connected to the chatroom")
        return

    nickname = userentry.get()
    userentry.delete(0, END)

    # update user list
    try_join(chatroom_name)

    if not nickname:
        # No nickname is provided, display the list of nicknames in the chatroom

        CmdWin.insert(1.0, "\nTo whom do you want to send the poke?\n"
                      + " ".join(user_list.get_names()))

        return
    else:
        peer = user_list.get_user_from_name(nickname)

        if not peer:
            CmdWin.insert(1.0, "\nThe selected user is not in the chatroom!")
            return

        if peer.name == me.name:
            CmdWin.insert(1.0, "\nYou cannot poke yourself!")
            return

        print("[debug] executing peer.send_poke()")
        peer.send_poke()


def do_Quit():
    CmdWin.insert(1.0, "\nPress Quit")
    close_ports()
    sys.exit(0)


def close_ports():
    # close all ports and free resources

    poke_sck.close()
    bwd_sck.close()

    for i in range(user_list.length):
        sck = user_list.get_element(i).get_socket()
        if sck:
            sck.close()
    server_sck.close()


#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

# Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

# Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='6', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8)
Butt02 = Button(topmidframe, width='6', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8)
Butt03 = Button(topmidframe, width='6', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8)
Butt04 = Button(topmidframe, width='6', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8)
Butt06 = Button(topmidframe, width='6', relief=RAISED, text="Poke", command=do_Poke)
Butt06.pack(side=LEFT, padx=8, pady=8)
Butt05 = Button(topmidframe, width='6', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8)

# Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

# Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)


def main():
    global me

    if len(sys.argv) != 4:
        print("P2PChat.py <server address> <server port no.> <my port no.>")
        sys.exit(2)

    me.set_port(sys.argv[3])
    me.set_msgID(0)
    setup_UDP()
    user_list.add_user(me)
    connect_server()
    win.mainloop()


if __name__ == "__main__":
    main()
