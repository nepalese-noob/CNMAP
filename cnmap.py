from tkinter import *
from PIL import Image, ImageTk
import subprocess
def heartbleed(): #nmap -sV -p 443 --script=ssl-heartbleed $webip
	
	print("You Can Learn More About HeartBleed Attack Or SSL HeartBleed Vulnerability")
	print("https://heartbleed.com")
	print("don't Worry Its Safe.Not Believeing Use VPN Hackers Style......")
	print("✓")
	six=s.get()
	five=("--script=ssl-heartbleed")
	four=("443")
	three=("-p")
	two=("-sV")
	one=("nmap")
	nmap=one,two,three,four,five,six
	print("your script is:" ,nmap)
	subprocess.call(nmap)
def printt():
	
	print(s.get())

def ExploitingVunerabilities():
	pass
def VulnerabilityScanning():
	def startvuln():
		three=s.get()
		two=("--script=vuln")
		one=("nmap")
		nmap=one,two,three
		print("your script is:" ,nmap)
		
		subprocess.call(nmap)
		pass
	def vpo():
		four=s.get()
		three=("-T0")
		two=("--script=vuln")
		one=("nmap")
		nmap=one,two,three,four
		print("your script is:" ,nmap)
		subprocess.call(nmap)	
	def vp():
		four=s.get()
		three=p.get()
		two=("--script=vuln")
		one=("nmap")
		nmap=one,two,three,four
		print("your script is:" ,nmap)
		subprocess.call(nmap)	
	def vv(): 
		four=s.get()
		three=("-sV")
		two=("--script=vuln")
		one=("nmap")
		nmap=one,two,three,four
		print("your script is:" ,nmap)
		subprocess.call(nmap)	
	def vs():
		four=s.get()
		three=("-T1")
		two=("--script=vuln")
		one=("nmap")
		nmap=one,two,three,four
		print("your script is:" ,nmap)
		subprocess.call(nmap)		
	def vpolit():
		four=s.get()
		three=("-T2")
		two=("--script=vuln")
		one=("nmap")
		nmap=one,two,three,four
		print("your script is:" ,nmap)
		subprocess.call(nmap)	
	def vin(): 
		four=s.get()
		three=("-T5")
		two=("--script=vuln")
		one=("nmap")
		nmap=one,two,three,four
		print("your script is:" ,nmap)
		subprocess.call(nmap)		
	def vag():
		four=s.get()
		three=("-T4")
		two=("--script=vuln")
		one=("nmap")
		nmap=one,two,three,four
		print("your script is:" ,nmap)
		subprocess.call(nmap)	
	def combo():
		four=st.get()
		five=s.get()
		three=varbo.get()
		two=("--script=vuln")
		one=("nmap")
		zero=("sudo")
		nmap=zero,one,two,three,four,five
		print("your script is:" ,nmap)
		subprocess.call(nmap)	
	vuln= Tk()
	vuln.title("choose one and lets have coffee..")
	Vulnscan = Button(vuln, text = "Vulnscan" , command = startvuln).grid()
	Vulnscan = Button(vuln, text = "Vulnscan + Paranoid Scan " , command = vpo).grid()
	Vulnscan = Button(vuln, text = "Vulnscan + Portscan" , command =vp).grid()
	Vulnscan = Button(vuln, text = "Vulnscan + Version Scan" , command =vv).grid()
	Vulnscan = Button(vuln, text = "Vulnscan + Sneaky Scan" , command = vs).grid()
	Vulnscan = Button(vuln, text = "Vulnscan + Polite Scan" , command = vpolit).grid()
	Vulnscan = Button(vuln, text = "Vulnscan + Insane Scan" , command = vin).grid()
	Vulnscan = Button(vuln, text = "Vulnscan + Aggressive Scan" , command = vag).grid()
	Vulnscan = Button(vuln, text = "Vulnscan + Verbosity Scan + ScanType + Timing Options " , command = combo).grid()
	vuln.mainloop()
	pass
def scriptscanner():
	pass
def about():
	rootabout=Tk()
	rootabout.geometry("1300x100+300+720")
	rootabout.title("Itni jaldi kya hai, abhi to mene start kiya he, (keep following...)")
	label = Label(rootabout,text='''This Script Is Based On python Tkinter Tool Or Script Which Will Use Nmap Switches and All The Possible and Always used Combinations,of Switches and Scanning Types for Evasion,Penetration,Aggressive etc...
	This Tool is The Automation of Nmap -> Custom Nmap (cnmap)
	if You Are Facing Problem We Are Making Tutorial on our group (dark hackers)
	You Can Contact Us on +977-9809642422
	bash script is also available by hawkhacker:
	the bash tool clone script is:
	git clone https://github.com/HawkHackers900/cnmap
	Enjoy''').pack()
	rootabout.mainloop()
	pass	
def guide():
	def basic():
		basic = Tk()
		basic.title("[1]Basic Syntax")
		label= Label(basic,text='''
		
[1]Basic Syntax
Enter Options Only
nmap [ScanTypes] [Options] [Target]''').grid()
		basic.mainloop()
	def Target():
		basic = Tk()
		basic.title("[2]Target Specification")
		label= Label(basic,text='''
[2]Target Specification
This is Just Like a Manual Guide
IPv4:127.0.0.1
IPv6:ABCD:CCDD::FF%eth0
Hostname:www.example.com
Ip address ranging 192.168.0-255.0-255
CIBR Blocks: 192.168.20.12/56 This Will Scan untill last number be 56
if you want to scan A Big List Use this switch
nmap -iL (filename) here -iL stand for list''').grid()
		basic.mainloop()
	def port():
			basic = Tk()
			basic.title("[3]Target Port")
			label= Label(basic,text='''
[3]Target Port
-F Scan 100 Most Popular Ports
-p<port-1> -> <port-2> Specific port Ranges
-r Scan Linear
--top-ports <n> Scan Most Popular Ports for open ports and Filtered ports
-p <Specific ports>''').grid()
		
	def probing():
			basic = Tk()
			basic.title("[4]Probing Options")
			label= Label(basic,text='''
[4]Probing Options
Probing Options Guide In Nmap
-Pn Condiders All Host are up
-PB Default Probes For (TCP 80 ICMP)
-Ps <Portlist>
-Pe ICMP request
-Pp Timestamp Request
-Pm ICMP Netmask''').grid()
	def scan():
			basic = Tk()
			basic.title("[5]Scan Types")
			label= Label(basic,text='''
[5]Scan Types
Scanning Types Guide
-sn Probe Scan
-sS SYN Scan First Handshake
-sT TCP Scan
-sU UDP Scan
-sV Version Scan For Servers
-O Operating System Detection Of The Service or Server
--scanflags Scan For Flag in CTF''').grid()

	def timing():
			basic = Tk()
			basic.title("[6]Timing Options")
			label= Label(basic,text='''
[6]Timing Options
Timing Options Guide
-T0 (paranoid Scan) Very Slow Scan for IDS Evasions
-T1 (Quite Slow) IDS Evasion
-T2 (Polite Scan) 10 Times Slower But effective to infiltrate network and Servers
-T3 (Default Scan) mention or Not Doesnt matter is Normal
-T4 (Aggressive) Fast Scan May Overwhelm Target and Sometimes Server detect and Blocks
-T5 (Insane Scan) Very Resource Consuming
-vv 1 -> 4 Verbosity Scan As You Decrease Time The More You Get Caught and Blocked''').grid()
	def output():
			basic = Tk()
			basic.title("[7]Output Formats")
			label= Label(basic,text='''
[7]Output Formats
Output Formats and Methods Guide For Nmap
-oN Standard Output
-oG Grappable Format
-oX XML format
-oA (Grappable XML txt etc)''').grid()


	def misc():
			basic = Tk()
			basic.title("[8]Misc Options")
			label= Label(basic,text='''
[8]Misc Options
Misc Options
-n Disable Reverse IP
-6 IPv6 Scan
-A Use Services OS,Version Detection,Traceroute etc (Fast Too)''').grid()
	guid= Tk()
	guid.title("Guide")
	button=Button(guid,text="[1]Basic Syntax",command=basic).grid()
	button=Button(guid,text="[2]Target Specification",command=Target).grid()
	button=Button(guid,text="[3]Target Port",command=port).grid()
	button=Button(guid,text="[4]Probing Options",command=probing).grid()
	button=Button(guid,text="[5]Scan Types",command=scan).grid()
	button=Button(guid,text="[6]Timing Options",command=timing).grid()
	button=Button(guid,text="[7]Output Formats",command=output).grid()
	button=Button(guid,text="[8]Misc Options",command=misc).grid()
	guid.mainloop()
	
def normalipscanner():
	def ipt():
		
		four=s.get()
		three=("https://ipinfo.io/")
		combo=(three+four)
		two=("-LO")
		one=("curl")
		nmap=one,two,combo
		print("your script is:" ,nmap)
		subprocess.call(nmap)
		
	def ips():
		two=s.get()
		one=("nmap")
		nmap=one,two
		print("your script is:" ,nmap)
		subprocess.call(nmap)
		
	ip = Tk()
	ip.title("trust yourself")
	label=Label(ip,text="choose",bg="blue",fg="red",font=("Times", "24", "bold italic")).grid()
	click =Button(ip,text="ip scanning",command=ips).grid()
	click =Button(ip,text="ip Tracing",command=ipt).grid()
	
	ip.mainloop()
def help():
	help=Tk()
	help.title("me hu na bhai, chinta mat lo' lets hace coffee")
	label=Label(help,text= 
	'''guys,
if you want any kind of solution
	or any kind 
of help, or want to report some issue
	please contact:+9779809642422
or ask in our whatsapp group''').pack(side=LEFT,anchor="nw")
	help.mainloop()

def scanner():
	def basic():
		pass
	def webscanning():
		def display_selected():
			choice = (value_inside.get())
			print (choice)
			if choice == "ip scaning":
				two=s.get()
				one=("nmap")
				nmap=one,two
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="version scaning":
				three=s.get()
				two=("-sV")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="probe scaning":
				three=s.get()
				two=("-sn")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="SYN Scan(root)":
				seven=("--system-dns")
				six=("-vvv")
				three=s.get()
				five=("-sT")
				four=("-F")
				two=("-Pn")
				one=("nmap")
				su=("sudo")
				nmap=su,one,two,four,five,three,six,seven
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="TCP scan":
				print(s.get())
				three=s.get()
				two=("-sT")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="UDP Scan(no-root)":
				three=s.get()
				four=("-ddd")
				two=("-vvv")
				one=("-F")
				su=("nmap")
				nmap=su,one,two,four,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="flag scan":
				three=s.get()
				two=("--scanflags")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="Frag scan":
				three=s.get()
				two=("-F")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)				
			elif choice =="port range scanner":
				four=s.get()
				three= p.get()
				two=("-p")
				one=("nmap")
				nmap=one,two,three,four
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="probe scan":
				three=s.get()
				two=("-Pn")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="default probe scan":
				three=s.get()
				two=("-PB")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="portlist scanner":
				three=s.get()
				two=("-PS")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="ICMP scan":
				three=s.get()
				two=("-PE")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="Reverse IP scan":
				three=s.get()
				two=("-n")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="IPv6 scan":
				three=s.get()
				two=("-6")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="aggressive scan(-A)":
				three=s.get()
				two=("-A")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="Paranoid scan":
				three=s.get()
				two=("-T0")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="sneaky scan":
				three=s.get()
				two=("-T1")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="polite scan":
				three=s.get()
				two=("-T2")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="normal scan":
				three=s.get()
				two=("-T3")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="Aggresive scan":
				three=s.get()
				two=("-T4")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
			elif choice =="Insane scan":
				three=s.get()
				two=("-T5")
				one=("nmap")
				nmap=one,two,three
				print("your script is:" ,nmap)
				subprocess.call(nmap)
		import tkinter
		web = tkinter.Tk()
		web.title("Hackers love coffee...do you love??")
		web.geometry('300x150+1000+470')
		options_list = ['ip scaning',
				'version scaning',
				'probe scaning',
				'SYN Scan(root)',
				'TCP scan',
				'UDP Scan(no-root)',
				'flag scan',
				'Frag scan',
				'port range scanner', 
				'probe scan', 
				'default probe scan', 
				'portlist scanner', 
				'ICMP scan', 
				'Reverse IP scan', 
				'IPv6 scan', 
				'aggressive scan(-A)',
				'Paranoid scan', 
				'sneaky scan', 
				'polite scan',
				'normal scan',
				'Aggresive scan',
				'Insane scan']
		value_inside = tkinter.StringVar(web)
		value_inside.set("Select an Option")
		question_menu = tkinter.OptionMenu(web, value_inside, *options_list)
		question_menu.pack()
		def print_answers():
			print("Selected Option: {}".format(value_inside.get()))
			return None
		submit_button = tkinter.Button(web, text='Submit', command=display_selected)		
		submit_button.pack()
		web.mainloop()
	def Advanced():
		def starth():
			three=s.get()
			two=("-T0")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		def starth2():
			three=s.get()
			two=("-6")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
			pass	
		kt =Tk()
		kt.title("final")
		firewall=Button(kt,text="[1]Firewall Evasion Combinations",command=starth).grid()
		ipv6=Button(kt,text="[2]IPv6 Scanning",command=starth2).grid()		
		pass
		kt.mainloop()
	scan=Tk()
	scan.title("choose scan types")
	basic=Button(scan,text="Basic",command=webscanning).grid()
	Advanced=Button(scan,text="Advanced",command=Advanced).grid()	
	scan.mainloop()
def webscanning():
	def display_selected():
		choice = (value_inside.get())
		print (choice)
		if choice == "ip scaning":
			two=s.get()
			one=("nmap")
			nmap=one,two
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="version scaning":
			three=s.get()
			two=("-sV")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="probe scaning":
			three=s.get()
			two=("-sn")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="SYN Scan(root)":
			seven=("--system-dns")
			six=("-vvv")
			three=s.get()
			five=("-sT")
			four=("-F")
			two=("-Pn")
			one=("nmap")
			su=("sudo")
			nmap=su,one,two,four,five,three,six,seven
			print("your script is:" ,nmap)
			subprocess.call(nmap)			
		elif choice =="TCP scan":
			print(s.get())
			three=s.get()
			two=("-sT")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
			
		elif choice =="UDP Scan(no-root)":
			three=s.get()
			four=("-ddd")
			two=("-vvv")
			one=("-F")
			su=("nmap")
			nmap=su,one,two,four,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="flag scan":
			three=s.get()
			two=("--scanflags")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="Frag scan":
			three=s.get()
			two=("-F")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)			
		elif choice =="port range scanner":
			five=s.get()
			four=p.get()
			two=("-p")
			one=("nmap")
			nmap=one,two,four,five
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="probe scan":
			three=s.get()
			two=("-Pn")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="default probe scan":
			three=s.get()
			two=("-PB")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="portlist scanner":
			three=s.get()
			two=("-PS")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="ICMP scan":
			three=s.get()
			two=("-PE")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="Reverse IP scan":
			three=s.get()
			two=("-n")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="IPv6 scan":
			three=s.get()
			two=("-6")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="aggressive scan(-A)":
			three=s.get()
			two=("-A")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="Paranoid scan":
			three=s.get()
			two=("-T0")
			one=("nmap")
			nmap=one,two,three
	
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="sneaky scan":
			three=s.get()
			two=("-T1")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="polite scan":
			three=s.get()
			two=("-T2")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="normal scan":
			three=s.get()
			two=("-T3")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="Aggresive scan":
			three=s.get()
			two=("-T4")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
		elif choice =="Insane scan":
			three=s.get()
			two=("-T5")
			one=("nmap")
			nmap=one,two,three
			print("your script is:" ,nmap)
			subprocess.call(nmap)
	import tkinter
	web = tkinter.Tk()
	web.title("I love coffee...do you love?")
	web.geometry('300x150+1000+470')
	options_list = ['ip scaning',
			'version scaning',
			'probe scaning',
			'SYN Scan(root)',
			'TCP scan',
			'UDP Scan(no-root)',
			'flag scan',
			'Frag scan',
			'port range scanner', 
			'probe scan', 
			'default probe scan', 
			'portlist scanner', 
			'ICMP scan', 
			'Reverse IP scan', 
			'IPv6 scan', 
			'aggressive scan(-A)',
			'Paranoid scan', 
			'sneaky scan', 
			'polite scan',
			'normal scan',
			'Aggresive scan',
			'Insane scan']
	value_inside = tkinter.StringVar(web)
	value_inside.set("Select an Option")
	question_menu = tkinter.OptionMenu(web, value_inside, *options_list)
	question_menu.pack()
	def print_answers():
		print("Selected Option: {}".format(value_inside.get()))
		return None
	submit_button = tkinter.Button(web, text='Submit', command=display_selected)
	
	submit_button.pack()

	web.mainloop()
def macspoof():
	def rm():
		four=s.get()
		three=("0")
		two=("--spoof-mac")
		one= ("nmap")
		Random=one,two,three,four
		print(Random)
		subprocess.Popen(Random)
	def cm():
		four=s.get()
		three= mac.get()
		two=("--spoof-mac")
		one= ("nmap")
		Ran=one,two,three,four
		print(Ran)
		subprocess.Popen(Ran)
		
	maccc=Tk()
	maccc.title("mac spoofing")
	rndm=Button(maccc,text="Random mac spoofing",command=rm).grid()
	cstm=Button(maccc,text="custom mac spoofing",command=cm).grid(row=1)
	maccc.mainloop()
	pass
def install():
	yes=("-y")
	three=("nmap")
	two=("install")
	one=("apt")
	su=("sudo")
	install=su,one,two,three,yes
	print(install)
	subprocess.call(install)
root = Tk()
labelimage = Label(root)
labelimage.grid(column=1,sticky="e")
filename = 'plane.jpg'
img = Image.open(filename)
resized_img = img.resize((200, 150))
root.photoimg = ImageTk.PhotoImage(resized_img)
labelimage.configure(image=root.photoimg)
label=Label(root,text="website or ip: ",font="default 19 bold",anchor="e").grid(row=1,column=0,sticky="w")
global website
s= StringVar()
website=Entry(root,textvariable=s).grid(row=1,column=0,pady=20,sticky="e")
label=Label(root,text="Fill port or portrange: ",font="default 19 bold",anchor="e").grid(row=1,column=1,sticky="e")
global port
p= StringVar()
port=Entry(root,textvariable=p).grid(row=1,column=2,pady=20,sticky="w")
global scantype
st= StringVar()
scantype=Entry(root,textvariable=st).grid(row=2,column=0,pady=20,sticky="e")
label=Label(root,text="Fill scantype: ",font="default 19 bold",anchor="e").grid(row=2,column=0,sticky="w")
global Verbosity
varbo= StringVar()
Verbosity=Entry(root,textvariable=varbo).grid(row=2,column=2,pady=20,sticky="w")
label=Label(root,text="Fill verbosity level: ",font="default 19 bold",anchor="e").grid(row=2,column=1,sticky="e")
global timing
tm= StringVar()
timing=Entry(root,textvariable=tm).grid(row=2,column=3,pady=20,sticky="e")
label=Label(root,text="Fill Timing: ",font="default 19 bold",anchor="e").grid(row=2,column=3,sticky="w")

global mac
mac= StringVar()
macc=Entry(root,textvariable=mac).grid(row=0,column=1,pady=20,sticky="w")
label=Label(root,text="Fill Custom Mac: ",font="default 19 bold",anchor="e").grid(row=0,column=0,sticky="e")



p.set("8080")
s.set("127.0.0.1")
tm.set("10")
varbo.set("-vv1,2,3,4,5")
st.set("-sS,-sT,-sV")
root.title("cnmap")
root.geometry("1625x500+150+1450")
install = Button(root,text="intall nmap",command= install,font="default 19 bold" ,bg="blue",fg="yellow").grid(padx=5, row=3,column=0)
fundamental = Button(root,text="MAC Spoofing",command=macspoof,font="default 19 bold" ,bg="blue",fg="orange").grid(padx=5,row=3,column=1)
webscanning= Button(root,text="webscanning",command=webscanning,font="default 19 bold" ,bg="blue",fg="yellow").grid(padx=5,row=3,column=2)
scanner= Button(root,text="scanner{basic & Advanced}",command=scanner,font="default 19 bold" ,bg="blue",fg="yellow").grid(padx=5,row=3,column=3)
lebal = Label(root, text="......................").grid(row=4)
lebal = Label(root, text="......................").grid(row=4,column=1)
lebal = Label(root, text="......................").grid(row=4,column=2)
lebal = Label(root, text="......................").grid(row=4,column=3)
normalipscanner= Button(root,text="normal ip scanner",command=normalipscanner,font="default 19 bold" ,bg="blue",fg="yellow").grid(padx=5,row=5,column=0)

scriptscanner= Button(root,text="script scanner {in progress}",command=scriptscanner,font="default 19 bold" ,bg="blue",fg="yellow").grid(padx=5,row=5,column=1)
VulnerabilityScanning= Button(root,text="Vulnerability Scanning",command=VulnerabilityScanning,font="default 19 bold" ,bg="blue",fg="yellow").grid(padx=5,row=5,column=2)
exploitVulnerability= Button(root,text="Exploit Vunerabilities[in progress]",command=ExploitingVunerabilities,font="default 19 bold" ,bg="blue",fg="yellow").grid(padx=5,row=5,column=3)
lebal = Label(root, text="......................").grid(row=6)
lebal = Label(root, text="......................").grid(row=6,column=1)
lebal = Label(root, text="......................").grid(row=6,column=2)
scriptscanner= Button(root,text="HeartBleed Scanner",command=heartbleed,font="default 19 bold" ,bg="blue",fg="yellow").grid(padx=5,row=8,column=0)
guide= Button(root,text="Network scanning guide",command=guide,font="default 19 bold" ,bg="red",fg="yellow").grid(padx=5,row=8,column=1)
about= Button(root,text="about",command=about,font="default 19 bold" ,bg="red",fg="yellow").grid(padx=5,row=8,column=2)
help= Button(root,text="help",command=help,font="default 19 bold" ,bg="red",fg="yellow").grid(padx=5,row=8,column=3)
root.mainloop()
