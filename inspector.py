#!/usr/bin/python

import SimpleHTTPServer
import SocketServer
import datetime
import os
import sys
import thread
import time
import traceback

HTTP_PORT = 8000

HTML_LINES = 1000

SWITCHES = {}


class SFlowSample():
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
            self.sflow_data[entry] = line_bits[index].lower()
            index += 1

        if self.sflow_data["sw_agn_ip"] in SWITCHES:
            SWITCHES[self.sflow_data["sw_agn_ip"]]["sample_rate"] = self.sflow_data["sample_rate"]

    def ip_version(self):
        if ":" in self.sflow_data["src_ip"]:
            return "ipv6"
        else:
            return "ipv4"

    def __getattr__(self, attr):
        if attr in self.sflow_data:
            return self.sflow_data[attr]
        else:
            return self.__getattribute__(attr)


class SFlowCounter():
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
            switch = SWITCHES[self.sflow_data["sw_agn_ip"]]
            self.prev_sflow_data = switch["interfaces"][int(self.sflow_data["if_index"])]

        SWITCHES[self.sflow_data["sw_agn_ip"]]["interfaces"][int(self.sflow_data["if_index"])] = self.sflow_data

    def __getattr__(self, attr):
        if attr in self.sflow_data:
            return self.sflow_data[attr]
        else:
            return self.__getattribute__(attr)

    def get_errors(self):
        error_msg = []
        if self.prev_sflow_data:
            in_discard_change = int(self.sflow_data["if_in_discards"]) - int(self.prev_sflow_data["if_in_discards"])
            if in_discard_change > 0:
                error_msg.append("Input discards increased by {} for interface {} on agent {}"
                                 .format(in_discard_change, self.sflow_data["if_index"], self.sflow_data["sw_agn_ip"]))
            in_error_change = int(self.sflow_data["if_in_errors"]) - int(self.prev_sflow_data["if_in_errors"])
            if in_error_change > 0:
                error_msg.append("Input errors increased by {} for interface {} on agent {}"
                                 .format(in_error_change, self.sflow_data["if_index"], self.sflow_data["sw_agn_ip"]))
            in_unknown_protos_change = int(self.sflow_data["if_in_unknown_protos"]) - \
                int(self.prev_sflow_data["if_in_unknown_protos"])
            if in_unknown_protos_change > 0:
                error_msg.append("Input unknown protocols increased by {} for interface {} on agent {}"
                                 .format(in_unknown_protos_change, self.sflow_data["if_index"],
                                         self.sflow_data["sw_agn_ip"]))
            out_discard_change = int(self.sflow_data["if_out_discards"]) - int(self.prev_sflow_data["if_out_discards"])
            if out_discard_change > 0:
                error_msg.append("Output discards increased by {} for interface {} on agent {}"
                                 .format(out_discard_change, self.sflow_data["if_index"], self.sflow_data["sw_agn_ip"]))
            out_error_change = int(self.sflow_data["if_out_errors"]) - int(self.prev_sflow_data["if_out_errors"])
            if out_error_change > 0:
                error_msg.append("Output errors increased by {} for interface {} on agent {}"
                                 .format(out_error_change, self.sflow_data["if_index"], self.sflow_data["sw_agn_ip"]))
        return error_msg


class SFlowTestResult():
    def __init__(self, error_present, error_msg=None, sample=None):
        self.error_present = error_present
        self.error_msg = error_msg
        self.sample = sample

    def is_error(self):
        return self.error_present

    def get_message(self):
        return self.error_msg

    def get_detail(self):
        if self.sample is not None:
            return "Agent: {} - Interface: {}->{} - MAC: {}->{} - IP: {}->{}" \
                   .format(self.sample.sw_agn_ip, self.sample.sw_in_port, self.sample.sw_out_port, self.sample.src_mac,
                           self.sample.dst_mac, self.sample.src_ip, self.sample.dst_ip)
        else:
            return None


class SFlowTests():
    def test_bad_mac(self, sample):
        bad_macs = ["000000000000"]
        if sample.src_mac in bad_macs:
            return SFlowTestResult(True, "Src MAC is invalid", sample)
        elif sample.dst_mac in bad_macs:
            return SFlowTestResult(True, "Dest MAC is invalid", sample)

        suspect_macs = ["deadbeef", "beefcafe"]
        for mac in suspect_macs:
            if mac in sample.src_mac:
                return SFlowTestResult(True, "Src MAC may be spoofed with string '{}'".format(mac), sample)
            elif mac in sample.dst_mac:
                return SFlowTestResult(True, "Dest MAC may be spoofed with string '{}'".format(mac), sample)

        return SFlowTestResult(False)

    def test_incorrect_multicast_mac(self, sample):
        if sample.ip_version() == "ipv4" and int(sample.dst_ip.split(".")[0]) >= 224 and \
                int(sample.dst_ip.split(".")[0]) <= 239:
            if sample.dst_mac[0:6] != "01005e":
                return SFlowTestResult(True, "Dest MAC is not a valid IPv4 multicast MAC", sample)
            else:
                correct_mac = "01005e" + hex(int(sample.dst_ip.split(".")[1]) & 0x7F)[2:].zfill(2) + \
                              hex(int(sample.dst_ip.split(".")[2]))[2:].zfill(2) + \
                              hex(int(sample.dst_ip.split(".")[3]))[2:].zfill(2)
                if sample.dst_mac != correct_mac:
                    return SFlowTestResult(True, "Dest MAC does not match the multicast IP address", sample)
        elif sample.ip_version() == "ipv6" and sample.dst_ip.split(":")[0][0:2] == "ff" and \
                sample.dst_ip.split(":")[0][2] != "0" and sample.dst_ip.split(":")[0][3] in ["2", "3", "4", "5", "8"]:
            if sample.dst_mac[0:4] != "3333":
                return SFlowTestResult(True, "Dest MAC is not a valid IPv6 multicast MAC", sample)
            else:
                correct_mac = "3333" + sample.dst_ip.split(":")[6].zfill(4) + sample.dst_ip.split(":")[7].zfill(4)
                if sample.dst_mac != correct_mac:
                    return SFlowTestResult(True, "Dest MAC does not match the multicast IP address", sample)
        elif int(sample.dst_mac[1], 16) & 0x1 == 1 and sample.dst_mac != "ffffffffffff":
            return SFlowTestResult(True, "Dest MAC indicates multicast, but IP address is not in the correct range",
                                   sample)

        return SFlowTestResult(False)


class Writer():
    def __init__(self, output_full, output_part):
        self.output_part = output_part
        self.output_file = open(os.path.dirname(os.path.realpath(__file__)) + "/" + output_full, "w", 0)
        self.last_write = 0
        self.html_lines = []

    def close(self):
        self.output_file.close()

    def write_message(self, type, message):
        styled_type = None
        if type.startswith("ERROR"):
            styled_type = "<span style='color: #ff0000; font-weight: bold'>{}:</span>".format(type)
        elif type.startswith("WARNING"):
            styled_type = "<span style='color: #ffa500; font-weight: bold'>{}:</span>".format(type)
        else:
            type = "UNKNOWN"
            styled_type = "<span style='color: #000000; font-weight: bold'>{}:</span>".format(type)

        dt = datetime.datetime.now()
        print("{} - {}: {}".format(dt, type, message))
        self.output_file.write("{} - {} {}<br />\n".format(dt, styled_type, message))

        self.html_lines.append("{} - {} {}<br />\n".format(dt, styled_type, message))
        while len(self.html_lines) > HTML_LINES:
            del self.html_lines[0]

        self.flush_buffer()

    def flush_buffer(self):
        if int(time.time()) > (self.last_write+1):
            self.last_write = int(time.time())
            with open(os.path.dirname(os.path.realpath(__file__)) + "/" + self.output_part, "w", 0) as partial_output:
                partial_output.write("".join(self.html_lines))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("python inspector.py <sflow-file-name>")
    else:
        tests = SFlowTests()
        sflow_file = open(sys.argv[1], 'r')
        os.chdir(os.path.dirname(os.path.realpath(__file__)) + "/html")
        writer = Writer("output_full.html", "output.html")
        handler = SimpleHTTPServer.SimpleHTTPRequestHandler
        httpd = SocketServer.TCPServer(("", HTTP_PORT), handler)
        thread.start_new_thread(httpd.serve_forever, ())
        print("* Starting HTTP server on port {}\n".format(HTTP_PORT))
        try:
            while True:
                new_line = sflow_file.readline()
                if new_line and len(new_line) > 4:
                    if new_line[0:4] == "FLOW":
                        try:
                            sample = SFlowSample(new_line)
                            result = tests.test_bad_mac(sample)
                            if result.is_error():
                                writer.write_message("ERROR", result.get_message())
                                writer.write_message("ERROR_DETAIL", result.get_detail())
                            result = tests.test_incorrect_multicast_mac(sample)
                            if result.is_error():
                                writer.write_message("ERROR", result.get_message())
                                writer.write_message("ERROR_DETAIL", result.get_detail())
                        except (IndexError, ValueError):
                            print("{} - INFO: Invalid sFlow sample. May be end of file. Ignoring"
                                  .format(datetime.datetime.now()))
                    elif new_line[0:4] == "CNTR":
                        try:
                            sample = SFlowCounter(new_line)
                            errors = sample.get_errors()
                            for error in errors:
                                writer.write_message("WARNING", error)
                        except (IndexError, ValueError):
                            print("{} - INFO: Invalid sFlow sample. May be end of file. Ignoring"
                                  .format(datetime.datetime.now()))
                else:
                    print("{} - INFO: Waiting for new data..."
                          .format(datetime.datetime.now()))
                    writer.flush_buffer()
                    time.sleep(1)
        except Exception:
            sflow_file.close()
            writer.close()
            httpd.shutdown()
            httpd.server_close()
            traceback.print_exc()
