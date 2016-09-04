# sFlow Packet Inspector

When run against a growing sFlow sampling file, this tool will attempt to identify cases of poorly constructed IP traffic.

This is intended for operation on small private networks.

## Issues Detected

* Sending to an incorrect MAC address for a given multicast IP
* Sending to a multicast MAC address without a multicast IP
* Sending to or from an all 0x00 MAC address
* Sending to or from common testing MACs such as 'deadbeef'
* Error and discard counts increasing on switch ports

## TODO

* Sending high volume multicast to groups not in the 232 or 239 ranges

Further issue detection will be added at a later date.
