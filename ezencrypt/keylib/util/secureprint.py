import sys
import msvcrt

def fallback_getpass(prompt='Password: ', stream=None):
    if not stream:
        stream = sys.stderr
    raise Exception("Cannot control stack")

def getpass_char(prompt='Password: ', stream=None, *, chr='*'):
    """Prompt for password with echo off, using Windows getwch()."""
    if sys.stdin is not sys.__stdin__:
        return fallback_getpass(prompt, stream)

    for c in prompt:
        msvcrt.putwch(c)
    pw = ""
    while 1:
        c = msvcrt.getwch()
        if c == '\r' or c == '\n':
            break
        if c == '\003':
            raise KeyboardInterrupt
        if c == '\b':
            if len(pw) > 0:
                msvcrt.putwch('\b')
                msvcrt.putwch(' ')
                msvcrt.putwch('\b')
                pw = pw[:-1]
        else:
            pw = pw + c
            msvcrt.putwch(chr)
    msvcrt.putwch('\r')
    msvcrt.putwch('\n')
    return pw

def printAndRemove(stuff : str):
    print("Secure print: Press any key to continue")
    for i in stuff:
        msvcrt.putwch(i)
    msvcrt.getwch()
    for i in range(len(stuff)):
        msvcrt.putwch('\b')
        msvcrt.putwch(' ')
        msvcrt.putwch('\b')
    endmsg = "Removed sensitive data succesfully"
    for i in endmsg:
        msvcrt.putwch(i)
    msvcrt.putwch("\n")