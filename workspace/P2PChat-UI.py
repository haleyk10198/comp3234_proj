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

#
# Global variables
#

username = ''
chatroom_name = ''
peer_sck = socket.socket()
server_sck = socket.socket()

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


def reconnect_server():
	CmdWin.insert(1.0, '\nConnection lost! attempting to reconnect ...')
	connect_server()


def connect_server():
	try:
		server_sck.connect((sys.argv[1], int(sys.argv[2])))
	except socket.error as err:
		print("Cannot connect to room server at '{}:{}'".format(sys.argv, sys.argv[2]))
		print('Error message: ', err)
		sys.exit(0)

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

	global username

	input_str = userentry.get()

	# insert check join condition here

	if not validate_name(input_str):
		outstr = "\n\'{}\' is an invalid username!".format(input_str)
	else:
		outstr = "\n[User] username: "+input_str
		username = input_str
		userentry.delete(0, END)

	CmdWin.insert(1.0, outstr)


def parse_semicolon_list(msg):
	# parse a ':' separated message into a list
	chatroom_list = msg.split(':')[1:-2]
	return chatroom_list


def do_List():
	CmdWin.insert(1.0, "\nPress List")

	try:
		server_sck.sendall('L::\r\n'.encode('utf-8'))
	except socket.error as err:
		pass

	return_msg = server_sck.recv(1000).decode('utf-8')

	if len(return_msg) == 0:
		reconnect_server()
		return
	elif return_msg[0] == 'F':
		output_str = '\nEncountered error:\n'+return_msg.split(':')[1]
	else:
		chatroom_list = parse_semicolon_list(return_msg)

		if len(chatroom_list) == 0:
			output_str = '\nNo active chatrooms'
		else:
			output_str = '\nHere are the active chatrooms:'
			for chatroom in chatroom_list:
				output_str += '\n\t'+chatroom

	CmdWin.insert(1.0, output_str)


def do_Join():

	global MSID, user_list, chatroom_name

	CmdWin.insert(1.0, "\nPress JOIN")
	output_str = ''

	if not username:
		CmdWin.insert(1.0, '\nPlease input your username first!')
		return

	if chatroom_name:
		CmdWin.insert(1.0, '\nYou have already joined a chatroom!')
		return

	input_str = userentry.get()
	if not validate_name(input_str):
		output_str = "\n\'{}\' is an invalid chatroom name!".format(input_str)
	else:
		userentry.delete(0, END)
		server_sck.sendall(
			"J:{}:{}:{}:{}::\r\n".format(input_str, username, server_sck.gethostname(), sys.argv[3]).encode('utf-8'))
		return_msg = server_sck.recv(1000).decode('utf-8')
		
		if len(return_msg) == 0:
			reconnect_server()
		elif return_msg[0] == 'F':
			output_str = '\nEncountered error:\n' + return_msg.split(':')[1]
		else:
			info_list = parse_semicolon_list(return_msg)
			MSID = info_list[0]
			user_list = [(info_list[i], info_list[i+1], info_list[i+2]) for i in range(1, len(info_list-1), 3)]
			chatroom_name = input_str

			# setup thread for executing keepalive

			# setup peer network

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
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)

	connect_server()

	win.mainloop()


if __name__ == "__main__":
	main()
