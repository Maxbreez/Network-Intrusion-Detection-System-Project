import PySimpleGUI as sg
import scapy.all as scp
import os
from scapy.all import sniff
import pyshark
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import codecs
import socket
import re
import json
import sys
import scapy.arch.windows as scpwinarch
import threading
import ipaddress
import subprocess
import yara
import pprint
import glob

#Reading and processing rules form rules.txt
def readrules():
    rulefile = "rules.txt"
    ruleslist = []
    with open(rulefile, "r") as rf:
        ruleslist = rf.readlines()
    rules_list = []
    for line in ruleslist:
        if line.startswith("alert"):
            rules_list.append(line)
    print(rules_list)
    return rules_list

alertprotocols = []
alertdestips = []
alertsrcips = []
alertsrcports = []
alertdestports = []
alertmsgs = []

#Processing rules to extract protocol, IPs, ports, and messages
def process_rules(rulelist):
    global alertprotocols
    global alertdestips
    global alertsrcips
    global alertsrcports
    global alertdestports
    global alertmsgs
    alertprotocols = []
    alertdestips = []
    alertsrcips = []
    alertsrcports = []
    alertdestports = []
    alertmsgs = []
    for rule in rulelist:
        rulewords = rule.split()
        if rulewords[1] != "any":
            protocol = rulewords[1]
            alertprotocols.append(protocol.lower())
        else:
            alertprotocols.append("any")
        if rulewords[2] != "any":
            srcip = rulewords[2]
            alertsrcips.append(srcip.lower())
        else:
            alertsrcips.append("any")
        if rulewords[3] != "any":
            srcport = int(rulewords[3])
            alertsrcports.append(srcport)
        else:
            alertsrcports.append("any")
        if rulewords[5] != "any":
            destip = rulewords[5]
            alertdestips.append(destip.lower())
        else:
            alertdestips.append("any")
        if rulewords[6] != "any":
            destport = rulewords[6]
            alertdestports.append(destport.lower())
        else:
            alertdestports.append("any")
        try:
            alertmsgs.append(" ".join([rulewords[x] for x in range(7, len(rulewords))]))
        except:
            pass

    print(alertprotocols)
    print(alertdestips)
    print(alertsrcips)
    print(alertsrcports)
    print(alertdestports)
    print(alertmsgs)

process_rules(readrules())    

deviceiplist = []
for route in scp.read_routes():
    if str(route[4]) not in deviceiplist:
        deviceiplist.append(str(route[4]))
        print(str(route[4]))

#Initializing GUI layout
sg.theme('BluePurple')

pktsummarylist = []
suspiciouspackets = []
suspacketactual = []
lastpacket = ""
sus_readablepayloads = []
all_readablepayloads = []
tcpstreams = []
SSLLOGFILEPATH = "C:\\Users\\Maxwell Kwaku Nyarko\\ssl1.log"
http2streams=[]
logdecodedtls = True
httpobjectindexes = []
httpobjectactuals = []
httpobjecttypes = []
yaraflagged_filenames = []
reqfilepathbase = "./temp/tcpflowdump/"

layout = [[sg.Button('STARTCAP', key="-startcap-"),
		sg.Button('STOPCAP', key='-stopcap-'), sg.Button('SAVE ALERT', key='-savepcap-'),
        sg.Button('REFRESH RULES', key='-refreshrules-'),
        sg.Button('LOAD TCP/HTTP2 STREAMS', key='-showtcpstreamsbtn-'),
        sg.Button('LOAD HTTP STREAMS', key='-showhttpstreamsbtn-'),
        sg.Button('YARA FILTER STREAMS', key='-yarafilterstreamsbtn-'),],
        [sg.Text("ALERT PACKETS", font=('Arial Bold', 14), size=(60, None), justification="left"),
         sg.Text("ALL PACKETS", font=('Arial Bold', 14), size=(60, None), justification="left")],
		[sg.Listbox(key='-pkts-', size=(100,20), values=suspiciouspackets, enable_events=True), 
        sg.Listbox(key='-pktsall-', size=(100,20), values=pktsummarylist, enable_events=True),
        ],
        [sg.Text("ALERT DECODED", font=('Arial Bold', 14), size=(35, None),justification="left"),
         sg.Text("HTTP2 STREAMS", font=('Arial Bold', 14),justification="left"),
         sg.Text("TCP STREAMS", font=('Arial Bold', 14),justification="left"),
         sg.Text("HTTP OBJECTS", font=('Arial Bold', 14),justification="left"),
         sg.Text("YARA FLAGGED STREAMS", font=('Arial Bold', 14),justification="left"),],
        [sg.Multiline(size=(60,20), key='-payloaddecoded-'),
        sg.Listbox(key='-http2streams-', size=(20, 20), values=http2streams, enable_events=True),
        sg.Listbox(key='-tcpstreams-', size=(20,20), values=tcpstreams, enable_events=True),
        sg.Listbox(key='-httpobjects-', size=(20, 20), values=httpobjectindexes, enable_events=True),
        sg.Listbox(key='-yaraflaggedstreams-', size=(40, 20), values=yaraflagged_filenames, enable_events=True),
        ],
		[sg.Button('EXIT')]]

window = sg.Window('Introduction', layout, size=(1600,800), resizable=True)

updatepktlist = False
pkt_list = []


#Getting HTTP headers
def get_http_headers(http_payload):
    try:
        headers_raw = http_payload[:http_payload.index(b"\r\n\r\n") + 2]
        headers = dict(re.findall(b"(?P<name>.*?): (?P<value>.*?)\\r\\n", headers_raw))
    except ValueError as err:
        logging.error('Could not find \\r\\n\\r\\n - %s' % err)
        return None
    except Exception as err:
        logging.error('Exception found trying to parse raw headers - %s' % err)
        logging.debug(str(http_payload))
        return None

    if b"Content-Type" not in headers:
        logging.debug('Content Type not present in headers')
        logging.debug(headers.keys())
        return None   
    return headers


#Funtiion to extract HTTP object
def extract_object(headers, http_payload):
    object_extracted = None
    object_type = None

    content_type_filters = [b'application/x-msdownload', b'application/octet-stream']

    try:
        if b'Content-Type' in headers.keys():          
            object_extracted = http_payload[http_payload.index(b"\r\n\r\n") +4:]
            object_type = object_extracted[:2]
            logging.info("Object Type: %s" % object_type)
        else: 
            logging.info('No Content Type in Package')
            logging.debug(headers.keys())

        if b'Content-Length' in headers.keys():
            logging.info( "%s: %s" % (b'Content-Lenght', headers[b'Content-Length']))
    except Exception as err:
        logging.error('Exception found trying to parse headers - %s' % err)
        return None, None
    return object_extracted, object_type

#Function to read HTTP packets
def read_http():
    objectlist = []
    objectsactual = []
    objectsactualtypes = []
    objectcount = 0
    global pkt_list
    try:
        os.remove(f".\\temp\\httpstreamread.pcap")
    except:
        pass
    httppcapfile = f".\\temp\\httpstreamread.pcap"
    scp.wrpcap(httppcapfile, pkt_list)
    pcap_flow = scp.rdpcap(httppcapfile)
    sessions_all = pcap_flow.sessions()

    for session in sessions_all:
        http_payload = bytes()
        for pkt in sessions_all[session]:
            if pkt.haslayer("TCP"):
                if pkt["TCP"].dport == 80 or pkt["TCP"].sport == 80 or pkt["TCP"].dport == 8080 or pkt["TCP"].sport == 8080:
                    if pkt["TCP"].payload:
                        payload = pkt["TCP"].payload
                        http_payload += scp.raw(payload)
        if len(http_payload):
            http_headers = get_http_headers(http_payload)

            if http_headers is None:
                continue

            object_found, object_type = extract_object(http_headers, http_payload)

            if object_found is not None and object_type is not None:
                objectcount += 1
                objectlist.append(objectcount-1)
                objectsactual.append(object_found)
                objectsactualtypes.append(object_type)
    
    return objectlist, objectsactual, objectsactualtypes

#Function to get protocol name by number
def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"

#Checking rules and generating warnings for suspicious packets.
def check_rules_warning(pkt):
    global alertprotocols
    global alertdestips
    global alertsrcips
    global alertsrcports
    global alertdestports
    global alertmsgs
    global sus_readablepayloads
    global updatepktlist

    if 'IP' in pkt:
        try:
            src = pkt['IP'].src
            dest = pkt['IP'].dst
            proto = proto_name_by_num(pkt['IP'].proto).lower()
            sport = pkt['IP'].sport
            dport = pkt['IP'].dport

            for i in range(len(alertprotocols)):
                flagpacket = False
                if alertprotocols[i] != "any":
                    chkproto = alertprotocols[i]
                else:
                    chkproto = proto
                if alertdestips[i] != "any":
                    chkdestip = alertdestips[i]
                else:
                    chkdestip = dest
                if alertsrcips[i] != "any":
                    chksrcip = alertsrcips[i]
                else:
                    chksrcip = src
                if alertsrcports[i] != "any":
                    chksrcport = alertsrcports[i]
                else:
                    chksrcport = sport
                if alertdestports[i] != "any":
                    chkdestport = alertdestports[i]
                else:
                    chkdestport = dport

                #Check for match with or without subnet
                if "/" not in str(chksrcip).strip() and "/" not in str(chkdestip).strip():
                    if (str(src).strip() == str(chksrcip).strip() and str(dest).strip() == str(chkdestip).strip() and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True
                if "/" in str(chksrcip).strip() and "/" in str(chkdestip).strip():
                    if (ipaddress.IPv4Address(str(src).strip()) in ipaddress.IPv4Network(str(chksrcip).strip()) and ipaddress.IPv4Address(str(dest).strip()) in ipaddress.IPv4Network(str(chkdestip).strip()) and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True
                if "/" in str(chksrcip).strip() and "/" not in str(chkdestip).strip():
                    if (ipaddress.IPv4Address(str(src).strip()) in ipaddress.IPv4Network(str(chksrcip).strip()) and str(dest).strip() == str(chkdestip).strip() and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True
                if "/" not in str(chksrcip).strip() and "/" in str(chkdestip).strip():                        
                    if (str(src).strip() == str(chksrcip).strip() and ipaddress.IPv4Address(str(dest).strip()) in ipaddress.IPv4Network(str(chkdestip).strip()) and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True

                if flagpacket == True:
                    if proto == "tcp":
                        try:
                            readable_payload = bytes(pkt['TCP'].payload).decode('UTF8','replace')
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting tcp payload!!")
                            print(ex)
                            pass
                    elif proto == "udp":
                        try:
                            readable_payload = bytes(pkt['UDP'].payload).decode('UTF8','replace')
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting udp payload!!")
                            print(ex)
                            pass
                    else:
                        sus_readablepayloads.append("NOT TCP PACKET!!")
                    if updatepktlist:
                        window['-payloaddecoded-'].update(value=sus_readablepayloads[len(suspiciouspackets)])
                    return True, str(alertmsgs[i])
        except:
            pkt.show()

    return False, ""

def pkt_process(pkt):
    global deviceiplist
    global window
    global updatepktlist
    global suspiciouspackets
    global all_readablepayloads

    pkt_summary = pkt.summary()
    pktsummarylist.append(f"{len(pktsummarylist)} " + pkt_summary)
    pkt_list.append(pkt)
    sus_pkt, sus_msg = check_rules_warning(pkt)
    if sus_pkt == True:
        suspiciouspackets.append(f"{len(suspiciouspackets)} {len(pktsummarylist) - 1}" + pkt_summary + f" MSG: {sus_msg}")
        suspacketactual.append(pkt)
    return

ifaces = [str(x["name"]) for x in scpwinarch.get_windows_if_list()]
capiface = ifaces[0]
sniffthread = threading.Thread(target=scp.sniff, kwargs={"prn":pkt_process, "filter": ""}, daemon=True)
sniffthread.start()

def show_tcp_stream_openwin(tcpstreamtext):
    layout = [[sg.Multiline(tcpstreamtext, size=(100,50), key="tcpnewwintext")]]
    window = sg.Window("TCPSTREAM", layout, modal=True, size=(1200, 600), resizable=True)
    choice = None
    while True:
        event, values = window.read()
        if event == "Exit" or event == sg.WIN_CLOSED:
            break
    window.close()

def show_http2_stream_openwin(tcpstreamtext):
    layout = [[sg.Multiline(tcpstreamtext, size=(100,50), key="tcpnewwintext")]]
    window = sg.Window("HTTP2 STREAM", layout, modal=True, size=(1200, 600), resizable=True)
    choice = None
    while True:
        event, values = window.read()
        if event == "Exit" or event == sg.WIN_CLOSED:
            break
    window.close()

def load_tcp_streams(window):
    global http2streams
    global logdecodedtls
    try:
        os.remove(f".\\temp\\tcpstreamread.pcap")
    except:
        pass
    scp.wrpcap(f".\\temp\\tcpstreamread.pcap", pkt_list)
    global tcpstreams
    tcpstreams = []
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"
    cap1 = pyshark.FileCapture(
        tcpstreamfilename,
        display_filter="tcp.seq==1 && tcp.ack==1 && tcp.len==0",
        keep_packets=True)
    number_of_streams = 0
    for pkt in cap1:
        if pkt.highest_layer.lower() == "tcp" or pkt.highest_layer.lower() == "tls":
            print(pkt.tcp.stream)
            if int(pkt.tcp.stream) > number_of_streams:
                number_of_streams = int(pkt.tcp.stream) + 1
    for i in range(0, number_of_streams):
        tcpstreams.append(i)
    window["-tcpstreams-"].update(values=[])
    window["-tcpstreams-"].update(values=tcpstreams)

    if logdecodedtls == True:
        http2streams = []
        cap2 = pyshark.FileCapture(
        tcpstreamfilename,
        display_filter="http2.streamid",
        keep_packets=True)
    
        for pkt in cap2:
            field_names = pkt.http2._all_fields
            for field_name in field_names:
                http2_stream_id = {val for key, val in field_names.items() if key == 'http2.streamid'}
                http2_stream_id = "".join(http2_stream_id)
            if http2_stream_id not in http2streams:
                http2streams.append(http2_stream_id)
        window['-http2streams-'].update(values=http2streams)
        pass

def show_http2_stream(window, streamno):
    
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"
    cap3 = pyshark.FileCapture(
            tcpstreamfilename,
            display_filter = f'http2.streamid eq {str(http2streamindex)}',
            override_prefs={'ssl.keylog_file': SSLLOGFILEPATH}
        )
    dat = ""
    decode_hex = codecs.getdecoder("hex_codec")
    http_payload = bytes()
    for pkt in cap3:
        try:
            payload = pkt["TCP"].payload
            http_payload += scp.raw(payload)
        except:
            pass

        print(pkt.http2.stream)
        if ("DATA" not in pkt.http2.stream):
            http2headerdat = ''
            rawvallengthpassed = False
            print(pkt.http2._all_fields.items())
            for field, val in pkt.http2._all_fields.items():
                if rawvallengthpassed == False:
                    if field == 'http2.header.name.length':
                        rawvallengthpassed = True
                else:
                    http2headerdat += str(field.split(".")[-1]) + " : " + str(val) + " \n"
                    print(http2headerdat)
            dat += "\n" + http2headerdat
            
    if len(http_payload):
        http_headers = get_http_headers(http_payload)

        if http_headers is not None:
            object_found, object_type = extract_object(http_headers, http_payload)

            dat += object_type + "\n" + object_found + "\n"

    print(dat)
    formatteddat = dat
    print(formatteddat)
    show_http2_stream_openwin(formatteddat)
    pass

def show_tcpstream(window, streamno):
    global SSLLOGFILEPATH
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"    
    streamnumber = streamno
    cap = pyshark.FileCapture(
        tcpstreamfilename,
        display_filter = 'tcp.stream eq %d' % streamnumber,
        override_prefs={'ssl.keylog_file': SSLLOGFILEPATH}
    )
    dat = b""
    decode_hex = codecs.getdecoder("hex_codec")
    for pkt in cap:
        try:
            payload = pkt.tcp.payload
            encryptedapplicationdata_hex = "".join(payload.split(":")[0:len(payload.split(":"))])
            encryptedapplicationdata_hex_decoded = decode_hex(encryptedapplicationdata_hex)[0]
            dat += encryptedapplicationdata_hex_decoded
        except Exception as ex:
            print(ex)

    formatteddat = str(dat, "ascii", "replace")

    if formatteddat.strip() == "" or len(str(formatteddat.strip)) < 1:
        sg.PopupAutoClose("No data")
    else:
        show_tcp_stream_openwin(formatteddat)


def yarascan(scanfile, rules):
    matches = []
    if os.path.getsize(scanfile) > 0:
        for match in rules.match(scanfile):
            matches.append({"name":match.rule, "meta":match.meta})

    return matches

def yarafilterstreams(window):      # window parameter for calling load_tcp_streams if necessary
    
    global yaraflagged_filenames
    global reqfilepathbase

    yaraflagged_filenames = []

    if not os.path.isfile("./temp/tcpstreamread.pcap"):
        load_tcp_streams(window)
    if not os.path.isfile("./temp/httpstreamread.pcap"):
        read_http()
    
    dumpfiles = glob.glob(reqfilepathbase + "*")
    for file in dumpfiles:
        os.remove(file)

    # generate files for packet streams using tcpflow
    subprocess.call("tcpflow64.exe -a -r temp/httpstreamread.pcap -o temp/tcpflowdump/", shell=True)
    subprocess.call("tcpflow64.exe -a -r temp/tcpstreamread.pcap -o temp/tcpflowdump/", shell=True)

    yarafile = "./yararules/rules1.yara"
    yararules = yara.compile(yarafile)      # compile yara rules

    
    matchcount = 1
    results = []
    resultstxt = ""
    for req in os.listdir(reqfilepathbase):
        res = yarascan(os.path.join(reqfilepathbase, req), yararules)
        if res:
            for match in res:
                pprint.pprint(match)
                results.append({"ruleMatched":match["name"]})
                resultstxt += str(matchcount) + ". " + str(match["name"]) + "\n"
                matchcount += 1
            if req != "report.xml":
                yaraflagged_filenames.append(str(match["name"]) + ":::" + req)  # ::: serves as separator
    with open("yararesults.txt", "w") as resfile:                       # for filename and yara rule name
        resfile.write(resultstxt)
    for file in yaraflagged_filenames:
        print(file)
    window["-yaraflaggedstreams-"].update(values=yaraflagged_filenames) #update gui with yara flagged stream filenames
    return

def show_yara_flagged(streamdat):
    layout = [[sg.Multiline(streamdat, size=(100,50), key="yaranewwintext")]]
    window = sg.Window("HTTP2 STREAM", layout, modal=True, size=(1200, 600), resizable=True)
    choice = None
    while True:
        event, values = window.read()
        if event == "Exit" or event == sg.WIN_CLOSED:
            break
    window.close()

def event_yaraflagged_selected(stream_idx):
    yarafilename = stream_idx.split(":::")[1]
    filepath = os.path.join(reqfilepathbase, yarafilename)
    with open(filepath, "r", errors="ignore") as yaraflaggedfile:
        yaraflagged_filedat = yaraflaggedfile.read()
    show_yara_flagged(yaraflagged_filedat)

while True:

    print(suspiciouspackets)

    event, values = window.read()
    if event == '-refreshrules-':
        process_rules(readrules())
    if event == "-startcap-":
        updatepktlist = True
        incomingpacketlist = []
        inc_pkt_list = []
        suspiciouspackets = []
        suspacketactual = []
        pktsummarylist = []
        sus_readablepayloads = []
        while True:
            event, values = window.read(timeout=10)
            if event == "-stopcap-":
                updatepktlist = False
                break
            if event == '-refreshrules-':
                process_rules(readrules())
            if event == sg.TIMEOUT_EVENT:
                window['-pkts-'].update(suspiciouspackets, scroll_to_index=len(suspiciouspackets))
                window['-pktsall-'].update(pktsummarylist, scroll_to_index=len(pktsummarylist))
            if event in (None, 'Exit'):
                sys.exit()
                break
            if event == '-pkts-' and len(values['-pkts-']):     
                sus_selected = values['-pkts-']
                sus_selected_index = values[event][0]
                try:
                    window["-tcpstreams-"].update(scroll_to_index=int(suspacketactual[sus_selected_index].tcp.stream))
                except:
                    pass
                window['-payloaddecoded-'].update(value=sus_readablepayloads[sus_selected_index ])
            if event == '-pktsall-' and len(values['-pktsall-']):     
                pkt_selected_index = window["-pktsall-"].get_indexes()
                try:
                    window["-tcpstreams-"].update(scroll_to_index=int(pkt_list[pkt_selected_index].tcp.stream))
                except:
                    pass
            if event == "-showtcpstreamsbtn-":      # load tcp streams btn
                load_tcp_streams(window)
            if event == "-tcpstreams-":
                streamindex = window["-tcpstreams-"].get_indexes()
                show_tcpstream(window, streamindex)
            if event == "-http2streams-":
                http2streamindex = values[event][0]
                show_http2_stream(window, int(http2streamindex))
            if event == "-showhttpstreamsbtn-":         # load http streams btn
                httpobjectindexes = []
                httpobjectactuals = []
                httpobjecttypes = []
                httpobjectindexes, httpobjectactuals, httpobjecttypes = read_http()
                window["-httpobjects-"].update(values=httpobjectindexes)
            if event == "-httpobjects-":
                httpobjectindex = values[event][0]
                show_http2_stream_openwin(httpobjecttypes[httpobjectindex] + b"\n" + httpobjectactuals[httpobjectindex][:900])
            if event == "-yarafilterstreamsbtn-":
                yarafilterstreams(window)
            if event == "-yaraflaggedstreams-":
                yaraflaggedstream_idx = values[event][0]
                event_yaraflagged_selected(yaraflaggedstream_idx)
    
    if event == "-yaraflaggedstreams-":
        yaraflaggedstream_idx = values[event][0]
        event_yaraflagged_selected(yaraflaggedstream_idx)

    if event == "-yarafilterstreamsbtn-":
        yarafilterstreams(window)

    if event == "-showhttpstreamsbtn-":
        httpobjectindexes = []
        httpobjectactuals = [] 
        httpobjecttypes = []
        httpobjectindexes, httpobjectactuals, httpobjecttypes = read_http()
        window["-httpobjects-"].update(values=httpobjectindexes)
    
    if event == "-httpobjects-":
        httpobjectindex = values[event][0]
        show_http2_stream_openwin(httpobjecttypes[httpobjectindex] + b"\n" + httpobjectactuals[httpobjectindex][:900])

    if event == "-http2streams-":
        http2streamindex = values[event][0]
        print(http2streamindex)
        show_http2_stream(window, str(int(http2streamindex)))
    if event == '-pktsall-' and len(values['-pktsall-']):     
        pkt_selected_index = window["-pktsall-"].get_indexes()[0]
        try:
            window["-tcpstreams-"].update(scroll_to_index=int(pkt_list[pkt_selected_index].tcp.stream))
        except:
            pass
    if event == '-savepcap-':
        pcapname = "nettrafic"
        scp.wrpcap(f'.\\savedpcap\\{pcapname}.pcap', inc_pkt_list)
    if event == '-pkts-' and len(values['-pkts-']):     
        sus_selected = values['-pkts-']
        sus_selected_index = window['-pkts-'].get_indexes()[0]
        try:
            window["-tcpstreams-"].update(scroll_to_index=int(suspacketactual[sus_selected_index].tcp.stream))
        except:
            pass
        window['-payloaddecoded-'].update(value=sus_readablepayloads[sus_selected_index])
    if event == "-showtcpstreamsbtn-":
        load_tcp_streams(window)    
    if event == "-tcpstreams-":
        streamindex = window["-tcpstreams-"].get_indexes()
        show_tcpstream(window, streamindex)
    if event in (None, 'Exit'):
        break

window.close()