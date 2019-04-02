from Tkinter import *
import os 
import py_compile

def convert():
    os.system("sudo python convertui.py")

def sniffer():
    os.system("sudo python sniffer.py")

    
if __name__=='__main__':
    main=Tk()
    main.geometry('700x700')
    main.title('Packet Sniffer')
    sniffer = Button(main, text="Sniffer", width=10, command=sniffer)
    sniffer.pack(padx=100, pady=100)
    convert = Button(main, text="Convert", width=10, command=convert)
    convert.pack()
    main.mainloop()
