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
        self.msgID = 0
        self.fwd = False
        self.bwd = False
        self.fwd_bwd_semaphore = threading.Semaphore(1)

    def get_msgID(self):
        return self.msgID

    def set_msgID(self, msgID):
        self.msgID = msgID

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

    # DONE: Lock declare_bwd and declare_fwd to ensure bwd == fwd == 1 never happens

    def declare_bwd(self):

        self.fwd_bwd_semaphore.acquire()

        # This is irreversible
        if not self.fwd:
            self.bwd = True  # target self

        bwd = self.bwd
        self.fwd_bwd_semaphore.release()

        return bwd

    def declare_fwd(self):

        self.fwd_bwd_semaphore.acquire()

        # This is irreversible
        if not self.bwd:
            self.fwd = True  # at most one

        fwd = self.fwd
        self.fwd_bwd_semaphore.release()

        return fwd

    def is_fwd(self):
        return self.fwd

    def is_bwd(self):
        return self.bwd


class UserList:

    lock = threading.Semaphore(1)

    def __init__(self):
        self.users = []
        self.fwd_count = 0  # at most one
        self.bwd_count = 0
        self.hash = -1

    def add_user(self, user):
        if user.hash not in [u.hash for u in self.users]:
            self.users.append(user)

    @staticmethod
    def acquire_lock():
        UserList.lock.acquire()

    @staticmethod
    def release_lock():
        UserList.lock.release()

    @property
    def length(self):
        return len(self.users)

    def get_element(self, i):
        return self.users[i]

    def declare_fwd(self, i):  # at most one, return once success or fail
        if self.fwd_count == 0:
            if self.users[i].declare_fwd():
                self.fwd_count += 1
                return True
        return False

    def declare_bwd(self, i):
        if self.users[i].declare_bwd():
            self.bwd_count += 1

    def get_hash(self):
        return self.hash

    def set_hash(self, hash):
        self.hash = hash

    def index(self, u):
        for i in range(0, len(self.users)):
            if self.users[i] == u:
                return i

        return -1


#
# Global variables
#

# me: self
me = User()
# chat room name joined
chatroom_name = ''
# fwd socket
peer_fwd_sck = socket.socket()
# bwd socket
bwd_sck = socket.socket()
# server socket
server_sck = socket.socket()
# holding users
user_list = UserList()
# bwd socket list
peer_bwd_socket_list = list()

# Assume max no of bwd peers is 5
MAX_BACKWARD_LINKS = 5


# randomly triggered by server, if not exist, add user. if exist, do nothing. return void
def update_members(instr):
    global user_list

    # Locking user list during updates
    UserList.acquire_lock()
    for i in range(0, len(instr), 3):
        user_list.add_user(User(instr[i], instr[i + 1], instr[i + 2]))
    UserList.release_lock()


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

    global bwd_sck

    bwd_sck.bind(('', int(me.get_port())))
    bwd_sck.listen(MAX_BACKWARD_LINKS)

    bwd_client_socket, addr = bwd_sck.accept()

    threading.Thread(target=bwd_handler, args=(bwd_client_socket, addr)).start()


def bwd_handler(bwd_client_socket, addr):
    global chatroom_name, user_list

    message = bwd_client_socket.recv(1000)

    # P:roomname:username:IP:Port:msgID::\r\n
    #      0        1      2  3    4
    message_contents = parse_semicolon_list(message.decode('utf-8'))

    # For updating the chatroom member list
    try_join(chatroom_name)

    id = user_list.index(User(message_contents[1], message_contents[2], message_contents[3]))
    # Check if user exists in list
    if id == -1:
        bwd_client_socket.close()
        return

    if user_list.get_element(id).declare_bwd(id):
        print("[debug] Received handshake request from {}, but failed to declare it as backwards".
              format(message_contents[1]))
        bwd_client_socket.close()
        return

    # Handshaking procedures -----------------------------

    # Print out bwd msg to command window
    CmdWin.insert(1.0, "A new backward link has come")

    # Add this new bwd new user to socket_list
    peer_bwd_socket_list.append(bwd_client_socket)

    # Set new msgID by increment 1
    me.set_msgID(me.get_msgID() + 1)
    handshake_msg = "S:" + str(me.get_msgID()) + "::\r\n"
    bwd_client_socket.send(handshake_msg.encode('utf-8'))


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

        my_id = user_list.index(me)

        for delta in range(1, user_list.length):
            start = (my_id + delta) % user_list.length
            peer = user_list.get_element(start)

            if peer.bwd:

                continue

            else:

                try:
                    peer_fwd_sck.connect((peer.addr, int(peer.port)))
                    peer_fwd_sck.sendall("P:{}:{}:{}:{}:{}::\r\n".format(
                        chatroom_name, me.get_name(), me.get_addr(), me.get_port(), me.get_msgID()
                    ).encode('utf-8'))
                    return_msg = peer_fwd_sck.recv(1000).decode('utf-8')

                    if len(return_msg) == 0:
                        peer_fwd_sck.close()
                        continue
                    else:
                        peer.set_msgID(parse_semicolon_list(return_msg[1]))
                        if user_list.declare_fwd(start):
                            break

                except socket.error:
                    continue
        else:
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
        CmdWin.insert(1.0, '\nMaintaining chatroom membership with server...')
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
            output_str = "\n You have successfully joined the chatroom \'{}\'!".format(chatroom_name)
            output_str += "\nList of members:"

            for i in range(0, user_list.length):
                output_str += "\n\t{}".format(user_list.get_element(i).get_name())

            # setup thread for executing keepalive
            threading.Thread(target=keep_alive).start()

            # setup peer network
            threading.Thread(target=select_peer).start()

            # handle bwd links
            threading.Thread(target=bwd_listener).start()

    CmdWin.insert(1.0, output_str)


def do_Send():
    CmdWin.insert(1.0, "\nPress Send")


def do_Poke():
    CmdWin.insert(1.0, "\nPress Poke")


def do_Quit():
    CmdWin.insert(1.0, "\nPress Quit")
    sys.exit(0)


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

    me.set_addr(socket.gethostname())
    me.set_port(sys.argv[3])
    user_list.add_user(me)
    connect_server()
    # add the thread to listen backwards
    win.mainloop()


if __name__ == "__main__":
    main()
