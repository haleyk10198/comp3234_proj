#!/usr/bin/python3

# Student name and No.:
# Student name and No.:
# Development platform:
# Python version:
# Version:


from tkinter import *
import sys
import socket

#
# Global variables
#

username = ''
peer_sck = socket.socket()
server_sck = socket.socket()

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


#
# Functions to handle user input
#

def validate_username(user):

	# rejects:
	# empty username
	# username with ':'

	if len(user) == 0:
		return False
	if user.find(':') != -1:
		return False

	return True


def do_User():

	# Must be executed to set username before joining any group
	# This function is only available before any successful joins

	global username

	input_str = userentry.get()

	# insert check join condition here

	if validate_username(username) == false:
		outstr = "\nUser name must not contain \':\'!"
	else:
		outstr = "\n[User] username: "+input_str
		username = input_str
		userentry.delete(0, END)

	CmdWin.insert(1.0, outstr)

def get_list(msg):
	chatroom_list = msg.split(':')[1:-2]
	return chatroom_list


def do_List():
	CmdWin.insert(1.0, "\nPress List")

	try:
		server_sck.sendall('L::\r\n'.encode('utf-8'))
	except socket.error as err:
		pass

	return_msg = server_sck.recv(1000)
	chatroom_list = get_list(return_msg)

	output_str = ''
	if len(chatroom_list) == 0:
		output_str = '\nNo active chatrooms'
	else:
		output_str = '\nHere are the active chatrooms:'
		for chatroom in chatroom_list:
			output_str += '\n\t'+chatroom
	CmdWin.insert(1.0, output_str)


def do_Join():
	CmdWin.insert(1.0, "\nPress JOIN")


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
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)

	try:
		server_sck.connect((sys.argv[1], int(sys.argv[2])))
	except socket.err as err:
		print("Cannot connect to room server at '{}:{}'".format(sys.argv, sys.argv[2]))
		print('Error message: ', err)
		return

	win.mainloop()


if __name__ == "__main__":
	main()
