# coding: utf-8

# # Generating Packets from STC for testing P4-based programs

# ## sridhar.rao@spirent.com and rahul.suryavanshi@spirent.com

import os
import logging
# To Avoid warnings.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import tasks
import importlib
import sys
import Tkinter, tkFileDialog
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from conf import settings as S
from StcPython import StcPython
_LOGGER = logging.getLogger(__name__)
_CURR_DIR = os.path.abspath('')

def create_scapy_out(fname):
    command = S.getValue('COMMAND')
    stdout, stderr = tasks.run_task([command, '-json', fname, '-o',
                                     '/tmp', '--scapy'], _LOGGER,
                                    'Create Dir', True)

def get_possible_packets():
    folder = os.path.join('/tmp', 'scapy')
    if os.listdir(folder):
        file = os.listdir(folder)[0]
        # fi = os.path.join(folder, file)
        print(folder)
        sys.path.append(folder)
        modname = file.split('.')[0]
        print(modname)
        # import modname
        module = __import__(modname)
        return module.possible_packets_

def get_customclass(name):
    folder = os.path.join('/tmp', 'scapy')
    if os.listdir(folder):
        file = os.listdir(folder)[0]
        sys.path.append(folder)
        modname = file.split('.')[0]
        fi = os.path.join(folder, modname)
        module = __import__(modname)
        cls = getattr(module, name)
        print(cls)
        return cls
        #rom  import *
    
       
def cleanup_scapy_files():
    folder = os.path.join('/tmp', 'scapy')
    if os.path.exists(folder):
        for file in os.listdir(folder):
            fi = os.path.join(folder, file)
            stdout, stderr = tasks.run_task(['rm', fi], _LOGGER,
                                            'Remove File', True) 

def get_p4program():
    root = Tkinter.Tk()
    root.withdraw()
    filename = tkFileDialog.askopenfilename()
    fname = filename.decode("utf-8")
    return fname 

def analyze_packet(p):
    layersStr = p.summary()
    layers = [x.strip() for x in layersStr.split('/')]
    layers.pop()
    for layer in layers:
        if 'Ether' in layer:
            print(p[Ether].dst)
            print(p[Ether].src)
            print(p[Ether].type)
        else:
            lyr = get_customclass(layer)
            field_names = [field.name for field in p[lyr].fields_desc]
            #fields = {field_name: getattr(p[lyr], field_name) for field_name in field_names}
            pattern = ''
            for field_name in field_names:
                v = getattr(p[lyr],field_name)
                pattern = pattern + str(v)
            pattern = '0x'+ pattern
            print(pattern)

def create_testcase(p, finame):
    print(p.show())
    stc = StcPython()
    hProject = stc.create("project")
    print("##### Create port #####")
    hPortTx = stc.create("port", under=hProject)
    print("##### creating the streamblock on port1 #####")
    hsb = stc.create("streamblock", under=hPortTx, load="10",
                     loadunit="PERCENT_LINE_RATE", insertSig="true",
                     frameLengthMode="FIXED", maxFrameLength="1200",
                     FixedFrameLength="256", frameconfig="")

    layersStr = p.summary()
    layers = [x.strip() for x in layersStr.split('/')]
    layers.pop()
    for layer in layers:
        if 'Ether' in layer:
            print("##### creating the Ethernet header #####")
            heth = stc.create("ethernet:EthernetII", under=hsb,
                              srcmac=p[Ether].src,
                              dstmac=p[Ether].dst)
        elif 'IP' in layer:
            print("##### creating the IPv4 header #####")
            hip = stc.create("ipv4:IPv4", under=hsb,
                             sourceaddr="10.10.10.1",
                             destaddr="10.10.10.2", 
                             gateway="10.10.10.2")
        elif 'TCP' in layer:
            print("#### creating tcp:TCP header ####")
            htcp = stc.create("tcp:TCP", under=hsb)
        elif 'UDP' in layer:
            print("#### creating udp:UDP header ####")
            htcp = stc.create("tcp:TCP", under=hsb)
        else:
            print("##### creating the custom header #####")
            lyr = get_customclass(layer)
            field_names = [field.name for field in p[lyr].fields_desc]
            #fields = {field_name: getattr(p[lyr], field_name) for field_name in field_names}
            pattern = ''
            for field_name in field_names:
                v = getattr(p[lyr],field_name)
                pattern = pattern + str(v)
            pattern = '0x'+ pattern
            hcp = stc.create("custom:Custom", under=hsb, pattern=pattern)

    print("##### Saving the config in XML file #####")
    stc.perform("saveasxml", filename=finame)

def main():
    # Read any Configuration
    S.load_from_dir(_CURR_DIR)

    # Cleanup any existing scapy files from /tmp/scapy folder.
    cleanup_scapy_files()

    # Get the P4 program from the user.
    # We will generate testcases to test this program.
    fname = get_p4program()

    # Create a scapy output for this program.
    create_scapy_out(fname)

    # Get all the possible packets to send to test the P4 Program.
    pp = get_possible_packets()

    # Create Test-Cases for each and every packet in the pssible-packet list
    index = 0
    filename = os.path.basename(fname)
    print(filename)
    tcprefix = filename.split('.')[0]
    print(tcprefix)
    for p in pp:
        # analyze_packet(p)
        destfile = tcprefix + str(index) + '.xml'
        dfile = os.path.join('/tmp', destfile)
        create_testcase(p, dfile)
        index = index + 1
        # return

if __name__ == '__main__':
    main()
