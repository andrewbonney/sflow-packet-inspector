# sFlow Packet Inspector

When run against a growing sFlow sampling file, this tool will attempt to identify cases of poorly constructed IP traffic.

This is intended for operation on small private networks.

## Issues Detected

* Sending high volume multicast to groups not in the 232 or 239 ranges
* Sending to a non-multicast MAC but with a multicast IP
* Sending to the wrong multicast MAC for a given multicast IP
* Sending to or from a zero MAC address, or a common testing MAC

Further issue detection will be added at a later date.
