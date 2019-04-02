from Tkinter import *                                           
import time                                                     
from tkFileDialog  import askopenfilename,asksaveasfilename    
import sys                                                      
import tkMessageBox                                             
import sniff
import thread
                                                     
curtime = ''
var = ' '

def SaveFile():
     asksaveasfilename(filetypes=[("PCAP file","*.pcap")],title="Save PCAP file")                                 

def quitGui():                                                                                             
     tkMessageBox.showinfo(title = 'Quit', message = "Do you really Want to Exit? ")                             
     main.destroy()

def tick():
        global curtime
        newtime = time.strftime('%H:%M:%S')
        if newtime != curtime:
            curtime = newtime
            clock.config(text=curtime)
        clock.after(200, tick)   

def threadone():
        try:
            listbox.insert(END,sniff.ret())
            thread.start_new_thread(sniff.sniff,())
            
        except (KeyboardInterrupt, SystemExit):
            cleanup_stop_thread();
            sys.exit()
            
def threadone2():
        try:
            listbox.insert(END," \n Finished Capturing packets \n")
            thread.start_new_thread(quitGui,())       
        except (KeyboardInterrupt, SystemExit):
            cleanup_stop_thread();
            sys.exit()


def threadinterrupt():
        thread.interrupt_main()                                                  
                                                                                       
if __name__=="__main__":
    main=Tk()                                               
    main.minsize(700,500)                                      
    main.maxsize(700,500)                                       
    main.geometry("700x500")                                     
    main.title("Packet Sniffer 0.1")                                                   
    menu= Menu(main)                                                                                                
    main.config(menu=menu)                                                                                            
    filemenu=Menu(menu)                                                                                            
    menu.add_cascade(label="File",menu=filemenu)                                                                                                                               
    filemenu.add_command(label="Save",underline=0,background='white',activebackground='orange',command=SaveFile)    
    filemenu.add_separator()                                                                                                                                       
    filemenu.add_command(label="Exit",command=main.quit)                                                            
    helpmenu=Menu(menu)                                                                                                
    fm = Frame(main, width=500, height=500,bg= "#374a89")                                                           
    xf2=Frame(main,height=200,width=500,bg="Blue")                                                                
    toolbar = Frame(main,  bg="#374a89" , relief='raised')
    b = Button(toolbar, text="Save", width=6, command=SaveFile)
    b.pack(side=LEFT, padx=2, pady=2)  
    saveandexit = Button(toolbar, text="  Exit  ", command=quitGui)
    saveandexit.pack(side=RIGHT, padx=2, pady=2,anchor=N)
    clock = Label(toolbar,bg='#374a89',fg='white')
    clock.pack(anchor=CENTER,padx=0)
    tick()  
    toolbar.pack(side=TOP, fill=BOTH,expand=NO)   
    SelectProtocol=Frame(fm,bg="Yellow",relief='ridge')
    SelectProtocol.pack(side=LEFT,anchor=NW,padx=1,pady=6)
    CountFrame=Frame(fm,relief='ridge',bg='yellow')
    CountFrame.pack(side=LEFT,pady=6,padx=1)
    scrollbar = Scrollbar(xf2)
    scrollbar.pack(side=RIGHT, fill=Y)
    listbox = Text(xf2, yscrollcommand=scrollbar.set,bg='black',fg='red')
    Z="Still waiting";
    listbox.insert(END,Z)
    listbox.pack(side=LEFT, fill=BOTH,expand=YES)
    scrollbar.config(command=listbox.yview)
    MainButton1=Button(fm,text="Stop Capture",bg="Red", fg="white",height=2,relief='ridge',activebackground='#eb0000',command=threadone2,activeforeground='white').pack(side=RIGHT,anchor=NE,pady=1,expand=YES,fill=X)
    MainButton=Button(fm,text="Start Capture",bg="#004e00", fg="white",height=2,relief='ridge',activebackground='#003a00',command=threadone,activeforeground='white').pack(side=RIGHT,anchor=NE,pady=1,padx=2,expand=YES,fill=X)
    fm.pack(side=TOP, expand=YES, fill=X)
    xf2.pack()
    main.mainloop()

   
    
