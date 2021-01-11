#! /usr/bin/python3
"""

Need to combine multiple scan results, sometimes they fail, run for different reasons.
nmap library written from perspective of regular scans, monitoring for differences. Our timeframe is singular from this standpoint.

results need to be cumulative, 
Need to keep most detailed results: empty script results should not blow away
only keep up hosts with open ports
only show open ports
"""

from libnmap.parser import NmapParser
import os, argparse

def crapscratch(chonk):
    
    for x in chonk:
        print(x)
        print("tcp: {}".format(" ".join(map(str, master[x]["tcp"].keys()))))
        print("udp: {}".format(" ".join(map(str, master[x]["udp"].keys()))))

def pips(res):
    #print IPs of results gonna do this too damn much to not be a func
    for h in res:
        print(h)

def portsearch(tmaster, proto, port, suss):
    res={}
    if port == 'a':
        for h in tmaster:
            #print(h)
            #print(master[h][proto])
            #print(len(master[h][proto]))
            if suss >= len(master[h][proto]) > 0:
                res[h] = master[h][proto].keys()
    else:
        for h in tmaster:
            #print(master[h][proto].keys())
            if int(port) in master[h][proto].keys():
                res[h] = ''

    return res
def showhost(tmaster, ip):
    res = {}
    for h in tmaster:
        if ip in h:
            res[h] = tmaster[h]
            #print(h)
    return res

def servicesearch(tmaster, service):
    #drill in and find service. drill it good.
    #looks in name & product
    res = []
    s = showsuss(tmaster, args.suss)
    for h in tmaster:
        if h in s:
            break
        for proto in tmaster[h]:
            for port in tmaster[h][proto]:
                #print(tmaster[h][proto][port])
                if "name" in tmaster[h][proto][port].keys():
                    if service.lower() in tmaster[h][proto][port]["name"].lower():
                        #print(tmaster[h][proto][port]["name"])
                        res.append([h, port, tmaster[h][proto][port]["name"]])
                if "product" in tmaster[h][proto][port].keys():
                    if service.lower() in tmaster[h][proto][port]["product"].lower():
                        #print(tmaster[h][proto][port]["name"])
                        res.append([h, port, tmaster[h][proto][port]["product"]])

    return res

def showsuss(tmaster, suss):
    #return a dict of machines that report a suspicious amount of ports open. probably giant liars.
    res = {}
    for h in tmaster:
        for proto in tmaster[h]:
            if suss <= len(master[h][proto]):
                res[h] = {}
                res[h][proto] = master[h][proto].keys()

    return res

#arg parser
parser = argparse.ArgumentParser(description='Make sense of all those damn scans')
parser.add_argument('-u', '--udp', help='Find hosts w/ UDP port. "a" for all UDP ports on any host')
parser.add_argument('-t', '--tcp', help='Find hosts w/ TCP port. "a" for all TCP ports on any host')
parser.add_argument('-i', '--ip', help='Show ports for a host (ip)')
parser.add_argument('-sv', '--service', help='Find hosts w/ service type. (http, ftp) prints proto & port')
parser.add_argument('-ss', '--showsuss', help='Show "suspicious" hosts, those ones with a few too many ports open', action='store_true')
parser.add_argument('-s', '--suss', help='Suspicious threshould; eg 25 open ports. Defaoult 25', type = int, default=25)
args = parser.parse_args()
#End argparser

scanpath = "external/nmap/"

rep = scanpath+"all.Pn.sS.TCP.allp.xml"

#rep = scanpath+"tg.3.UDP.def.xml"

scanpath = "external/nmap/"

#scanpath = "external/"


###### find XML reports, parse and collate!!!
reports = []

for file in os.listdir(scanpath):
    if file.endswith(".xml"):
        rep = scanpath+file
        print(rep)
        try:
            x = NmapParser.parse_fromfile(rep)
        except:
            print("busted XML? trying fix...")
            x = NmapParser.parse_fromfile(rep, incomplete=True)
        reports.append(x)


#master collection of details, accumulate most best info
master=dict()

for r in reports:
    for h in r.hosts:
        #print("**********************************")
        #if no open ports, don't care & skip
        if len(h.get_open_ports())>0:
            #will try to use length of sub dicts to keep most info, have to precreate key if not there
            #print(h.get_open_ports())
            if h.address in master.keys():
                pass
                #print("known")
            else:
                #print("adding new host: {}".format(h.address))
                master[h.address]={"tcp":{}, "udp":{}}

            #print(h.address)
            #print(h.get_dict())
            if h.services:
                #print(h.services)
                for s in h.services:
                   
                    #print(s)
                    #print(s.protocol)
                    #print(s.port)
                    if s.port in master[h.address][s.protocol].keys():
                        #if the current report port is in the masterm, check for length & update if better.
                        if len(s.service_dict) > len(master[h.address][s.protocol][s.port]):
                            master[h.address][s.protocol][s.port] = s.service_dict
                    else:
                        master[h.address][s.protocol][s.port] = s.service_dict
                    """
                    print(len(s.service_dict))
                    for head in s.service_dict:
                        print("service dict deet: {}".format(head))
                        print(s.service_dict[head])
                    print("--------------2-")
                    """
######




if args.udp:
    f = portsearch(master, "udp", args.udp, args.suss)
    print(f)

if args.tcp:
    f = portsearch(master, "tcp", args.tcp, args.suss)
    print(f)

if args.service:
    f = servicesearch(master, args.service)
    print(f)

if args.showsuss:
    f = showsuss(master, args.suss)
    pips(f)

if args.ip:
    f = showhost(master, args.ip)
    #print(f)
    crapscratch(f)

#print(master)
#print(args)