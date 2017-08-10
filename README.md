# FancyVote
My solution to the BFS Ekoparty Exploitation Challenge.

See https://labs.bluefrostsecurity.de/blog/2017/08/02/bfs-ekoparty-exploitation-challenge/


Placing a conditional breakpoint at 0x13F4913D7 (as shown below) suspends the process the moment the instruction pointer RIP is taken control of, having bypassed the stack cookie check and the payload set up on the stack already. The payload then causes the process to jump into a call to system(), then to return to the vulnerable function, bypassing the stack cookie once more before it finally jumps into ROP payload that adjusts the stack pointer by applying funky patches directly to the stack.

![Conditional breakpoint](/condbpt.png?raw=true)
![Payload](/fv.gif?raw=true)
