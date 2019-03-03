#!/usr/bin/python3

# Student name and No.: Kwok Kin Hei (3035 371 587)
# Student name and No.:
# Development platform:
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


class User:
    def __init__(self, name='', addr='0', port='0'):
        self.name = name
        self.addr = addr
        self.port = port
        self.hash = sdbm_hash(self.name + self.addr + self.port)
        self.msgID = -1

    def update_hash(self):
        self.hash = sdbm_hash(self.name + self.addr + self.port)

    def set_name(self, name):
        self.name = name
        self.update_hash()

    def get_name(self):
        return self.name

    def set_addr(self, addr):
        self.addr = addr
        self.update_hash()

    def get_addr(self):
        return self.addr

    def set_port(self, port):
        self.port = port
        self.update_hash()

    def get_port(self):
        return self.port

    def get_hash(self):
        return self.hash

#
# Global variables
#


me = User()
chatroom_name = ''
peer_fwd_sck = socket.socket()
peer_bwd_sck = socket.socket()
server_sck = socket.socket()

bck_links = []

MSID = -1
user_list = []

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


def update_members(instr):
    global user_list
    user_list = [User(instr[i], instr[i + 1], instr[i + 2]) for i in range(0, len(instr), 3)] + [me]
    user_list.sort(key=lambda user: user.get_hash)


def reconnect_server():
    CmdWin.insert(1.0, '\nConnection lost! attempting to reconnect ...')
    connect_server()


def connect_server():
    try:
        server_sck.connect((sys.argv[1], int(sys.argv[2])))
    except socket.error as err:
        print("Cannot connect to room server at '{}:{}'".format(sys.argv[1], sys.argv[2]))
        print('Error message: ', err)
        sys.exit(0)


def is_connected(sck):
    try:
        sck.getpeername()
        return True
    except socket.error:
        return False


def handshake(sck):
    pass


def select_peer():
    global user_list, me

    my_id = user_list.index(me)

    for delta in range(1, len(user_list)):
        start = (my_id + delta) % len(user_list)
        pass
    # TODO


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


def parse_semicolon_list(msg):
    # parse a ':' separated message into a list
    chatroom_list = msg.split(':')[1:-2]
    return chatroom_list


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


def do_Join():
    global MSID, user_list, chatroom_name, me

    CmdWin.insert(1.0, "\nPress JOIN")
    output_str = ''

    if not me.username:
        CmdWin.insert(1.0, '\nPlease input your username first!')
        return

    if chatroom_name:
        CmdWin.insert(1.0, '\nYou have already joined a chatroom!')
        return

    if not is_connected(server_sck):
        connect_server()

    input_str = userentry.get()
    if not validate_name(input_str):
        output_str = "\n\'{}\' is an invalid chatroom name!".format(input_str)
    else:
        userentry.delete(0, END)
        server_sck.sendall(
            "J:{}:{}:{}:{}::\r\n".format(input_str, me.username, me.addr, me.port).encode('utf-8'))
        return_msg = server_sck.recv(1000).decode('utf-8')

        if len(return_msg) == 0:
            reconnect_server()
        elif return_msg[0] == 'F':
            output_str = '\nEncountered error:\n' + return_msg.split(':')[1]
        else:
            info_list = parse_semicolon_list(return_msg[1:-1])
            MSID = int(info_list[0])
            update_members(info_list[1:])
            chatroom_name = input_str

            # setup thread for executing keepalive

            # setup peer network
            threading.Thread(target=select_peer)

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
    me.set_addr(sys.argv[3])
    connect_server()
    # add the thread to listen backwards
    win.mainloop()


if __name__ == "__main__":
    main()
