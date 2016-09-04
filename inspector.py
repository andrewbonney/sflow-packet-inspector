#!/usr/bin/python

import sys
import os
import SimpleHTTPServer
import SocketServer
import time
import thread
import traceback
import datetime

HTTP_PORT=8000

SWITCHES={}

class sFlowSample():
    def __init__(self, line):
        line_bits = line.split(",")
        sample_def = [
            "sw_agn_ip",
            "sw_in_port",
            "sw_out_port",
            "src_mac",
            "dst_mac",
            "eth_type",
            "in_vlan",
            "out_vlan",
            "src_ip",
            "dst_ip",
            "ip_proto",
            "ip_tos",
            "ip_ttl",
            "src_port",
            "dst port",
            "tcp_flags",
            "pkt_size",
            "ip_pkt_size",
            "sample_rate"
        ]

        self.sflow_data = {}
        index = 1
        for entry in sample_def:
            self.sflow_data[entry] = line_bits[index]
            index += 1

        if self.sflow_data["sw_agn_ip"] in SWITCHES:
            SWITCHES[self.sflow_data["sw_agn_ip"]]["sample_rate"] = self.sflow_data["sample_rate"]

    def __getattr__(self, attr):
        if attr in self.sflow_data:
            return self.sflow_data[attr]
        else:
            return self.__getattribute__(attr)


class sFlowCounter():
    def __init__(self, line):
        line_bits = line.split(",")
        counter_def = [
            "sw_agn_ip",
            "if_index",
            "if_type",
            "if_speed",
            "if_direction",
            "if_in_octets",
            "if_in_ucast_pkts",
            "if_in_mcast_pkts",
            "if_in_bcast_pkts",
            "if_in_discards",
            "if_in_errors",
            "if_in_unknown_protos",
            "if_out_octets",
            "if_out_ucast_pkts",
            "if_out_mcast_pkts",
            "if_out_bcast_pkts",
            "if_out_discards",
            "if_out_errors",
            "if_promiscuous_mode"
        ]

        self.sflow_data = {}
        self.prev_sflow_data = None

        index = 1
        for entry in counter_def:
            self.sflow_data[entry] = line_bits[index]
            index += 1

        if self.sw_agn_ip not in SWITCHES:
            SWITCHES[self.sflow_data["sw_agn_ip"]] = {"interfaces": [], "sample_rate": 4000}
        while len(SWITCHES[self.sflow_data["sw_agn_ip"]]["interfaces"]) < (int(self.sflow_data["if_index"]) + 1):
            SWITCHES[self.sflow_data["sw_agn_ip"]]["interfaces"].append(None)

        if SWITCHES[self.sflow_data["sw_agn_ip"]]["interfaces"][int(self.sflow_data["if_index"])] is not None:
            self.prev_sflow_data = SWITCHES[self.sflow_data["sw_agn_ip"]]["interfaces"][int(self.sflow_data["if_index"])]

        SWITCHES[self.sflow_data["sw_agn_ip"]]["interfaces"][int(self.sflow_data["if_index"])] = self.sflow_data

    def __getattr__(self, attr):
        if attr in self.sflow_data:
            return self.sflow_data[attr]
        else:
            return self.__getattribute__(attr)

    def getErrors(self):
        error_msg = []
        if self.prev_sflow_data:
            in_discard_change = int(self.sflow_data["if_in_discards"]) - int(self.prev_sflow_data["if_in_discards"])
            if in_discard_change > 0:
                error_msg.append("Input discards increased by {} for interface {} on agent {}".format(in_discard_change, self.sflow_data["if_index"], self.sflow_data["sw_agn_ip"]))
            in_error_change = int(self.sflow_data["if_in_errors"]) - int(self.prev_sflow_data["if_in_errors"])
            if in_error_change > 0:
                error_msg.append("Input errors increased by {} for interface {} on agent {}".format(in_error_change, self.sflow_data["if_index"], self.sflow_data["sw_agn_ip"]))
            in_unknown_protos_change = int(self.sflow_data["if_in_unknown_protos"]) - int(self.prev_sflow_data["if_in_unknown_protos"])
            if in_unknown_protos_change > 0:
                error_msg.append("Input unknown protocols increased by {} for interface {} on agent {}".format(in_unknown_protos_change, self.sflow_data["if_index"], self.sflow_data["sw_agn_ip"]))
            out_discard_change = int(self.sflow_data["if_out_discards"]) - int(self.prev_sflow_data["if_out_discards"])
            if out_discard_change > 0:
                error_msg.append("Output discards increased by {} for interface {} on agent {}".format(out_discard_change, self.sflow_data["if_index"], self.sflow_data["sw_agn_ip"]))
            out_error_change = int(self.sflow_data["if_out_errors"]) - int(self.prev_sflow_data["if_out_errors"])
            if out_error_change > 0:
                error_msg.append("Output errors increased by {} for interface {} on agent {}".format(out_error_change, self.sflow_data["if_index"], self.sflow_data["sw_agn_ip"]))
        return error_msg


class sFlowTestResult():
    def __init__(self, error_present, error_msg=None, sample=None):
        self.error_present = error_present
        self.error_msg = error_msg
        self.sample = sample

    def isError(self):
        return self.error_present

    def getMessage(self):
        if self.sample is not None:
            return self.error_msg + "\n- {} {}->{} {}->{} {}->{}".format(self.sample.sw_agn_ip, self.sample.sw_in_port, self.sample.sw_out_port, self.sample.src_mac, self.sample.dst_mac, self.sample.src_ip, self.sample.dst_ip)
        else:
            return self.error_msg


class sFlowTests():
    def testBadMAC(self, sample):
        BAD_MACS = ["000000000000"]
        if sample.src_mac in BAD_MACS:
            return sFlowTestResult(True, "Src MAC is invalid", sample)
        elif sample.dst_mac in BAD_MACS:
            return sFlowTestResult(True, "Dest MAC is invalid", sample)

        SUSPECT_MACS = ["deadbeef", "beefcafe"]
        for mac in SUSPECT_MACS:
            if mac in sample.src_mac:
                return sFlowTestResult(True, "Src MAC may be spoofed with string '{}'".format(mac), sample)
            elif mac in sample.dst_mac:
                return sFlowTestResult(True, "Dest MAC may be spoofed with string '{}'".format(mac), sample)

        return sFlowTestResult(False)

    def testIncorrectMulticastMAC(self, sample):
        if int(sample.dst_ip.split(".")[0]) >= 224 and int(sample.dst_ip.split(".")[0]) <= 239:
            if sample.dst_mac[0:6] != "01005e":
                return sFlowTestResult(True, "Dest MAC is not a valid multicast MAC", sample)
            else:
                correct_mac = "01005e" + hex(int(sample.dst_ip.split(".")[1]) & 0x7F)[2:].zfill(2) + hex(int(sample.dst_ip.split(".")[2]))[2:].zfill(2) + hex(int(sample.dst_ip.split(".")[3]))[2:].zfill(2)
                if sample.dst_mac != correct_mac:
                    return sFlowTestResult(True, "Dest MAC does not match the multicast IP address", sample)
        elif int(sample.dst_mac[1], 16) & 0x1 == 1 and sample.dst_mac != "ffffffffffff":
            return sFlowTestResult(True, "Dest MAC indicates multicast, but IP address is not in the correct range", sample)

        return sFlowTestResult(False)


def writeMessage(type, message, output_file):
    styled_type = None
    if type == "ERROR":
        styled_type = "<span style='color: #ff0000; font-weight: bold'>{}:</span>".format(type)
    elif type == "WARNING":
        styled_type = "<span style='color: #ffa500; font-weight: bold'>{}:</span>".format(type)
    else:
        type = "UNKNOWN"
        styled_type = "<span style='color: #000000; font-weight: bold'>{}:</span>".format(type)

    dt = datetime.datetime.now()
    print "{} - {}: {}\n".format(dt, type, message)
    output_file.write("{} - {} {}<br /><br />\n".format(dt, styled_type, message.replace("\n", "<br />\n")))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "python inspector.py <sflow-file-name>"
    else:
        tests = sFlowTests()
        output_file = open("html/output.html", "w", 0)
        sflow_file = open(sys.argv[1], 'r')
        os.chdir("html")
        handler = SimpleHTTPServer.SimpleHTTPRequestHandler
        httpd = SocketServer.TCPServer(("", HTTP_PORT), handler)
        thread.start_new_thread(httpd.serve_forever, ())
        print "* Starting HTTP server on port {}\n".format(HTTP_PORT)
        try:
            while True:
                new_line = sflow_file.readline()
                if new_line and new_line[0:4] == "FLOW":
                    sample = sFlowSample(new_line)
                    result = tests.testBadMAC(sample)
                    if result.isError():
                        writeMessage("ERROR", result.getMessage(), output_file)
                    result = tests.testIncorrectMulticastMAC(sample)
                    if result.isError():
                        writeMessage("ERROR", result.getMessage(), output_file)
                elif new_line and new_line[0:4] == "CNTR":
                    sample = sFlowCounter(new_line)
                    errors = sample.getErrors()
                    for error in errors:
                        writeMessage("WARNING", error, output_file)
                elif not new_line:
                    time.sleep(1)
        except Exception:
            sflow_file.close()
            output_file.close()
            httpd.shutdown()
            httpd.server_close()
            traceback.print_exc()
