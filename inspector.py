#!/usr/bin/python

import sys
import SimpleHTTPServer
import SocketServer
import time
import thread
import traceback

SFLOW_INTERVAL=4000
HTTP_PORT=8000

class sFlowSample():
    def __init__(self, line):
        self.src_mac = None
        self.dst_mac = None
        self.src_ip = None
        self.dst_ip = None


class sFlowTestResult():
    def __init__(self, error_present, error_msg=None):
        self.error_present = error_present
        self.error_msg = error_msg

    def isError(self):
        return self.error_present

    def getMessage(self):
        return self.error_msg


class sFlowTests():
    def testBadMAC(self, sample):
        BAD_MACS = ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"]
        if sample.src_mac in BAD_MACS:
            return sFlowTestResult(True, "Src MAC is invalid ({})".format(sample.src_mac))
        elif sample.dst_mac in BAD_MACS:
            return sFlowTestResult(True, "Dest MAC is invalid ({})".format(sample.dst_mac))
        
        return sFlowTestResult(False)

    def testIncorrectMulticastMAC(self, sample):
        if sample.dst_ip[0] >= 224 or sample.dst_ip[0] <= 239:
            if self.dst_mac[0:8] != "01:00:5e":
                return sFlowTestResult(True, "Dest MAC is not a valid multicast MAC ({})".format(sample.dst_mac))
            else:
                correct_mac = "01:00:5e:" + hex(sample.dst_ip[1] & 0x7F)[2:] + ":" + hex(sample.dst_ip[2])[2:] + ":" + hex(sample.dst_ip[3])[2:]
                if sample.dst_mac != correct_mac:
                    return sFlowTestResult(True, "Dest MAC does not match the multicast IP address ({})".format(sample.dst_mac))
        
        return sFlowTestResult(False)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "python inspector.py <sflow-file-name>"
    else:
        tests = sFlowTests()
        output_file = open("index.html", "w", 0)
        sflow_file = open(sys.argv[0], 'r')
        handler = SimpleHTTPServer.SimpleHTTPRequestHandler
        httpd = SocketServer.TCPServer(("", HTTP_PORT), handler)
        thread.start_new_thread(httpd.serve_forever, ())
        print "* Starting HTTP server on port {}".format(HTTP_PORT)
        output_file.write("<title>sFlow Packet Inspector</title>\n")
        try:
            while True:
                new_line = sflow_file.readline()
                if new_line:
                    sample = sFlowSample(new_line)
                    #result = tests.testBadMAC(sample)
                    #if result.isError():
                    #    output_file.write(result.getMessage() + "\n")
                    #result = tests.testIncorrectMulticastMAC(sample)
                    #if result.isError():
                    #    output_file.write(result.getMessage() + "\n")
                else:
                    time.sleep(1)
        except Exception:
            sflow_file.close()
            output_file.close()
            httpd.shutdown()
            httpd.server_close()
            traceback.print_exc()
