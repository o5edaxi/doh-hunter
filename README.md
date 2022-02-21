### What this does

This script reads [Zeek](https://zeek.org/) (formerly Bro) logs, the **ssl.log** specifically, and extracts the names and IP addresses of websites visited over HTTPS in the network being monitored.

It then proceeds to test these addresses for the presence of DNS over HTTPS (DoH) resolvers by sending a generic DNS query in both JSON and wire formats to the destination, and checking for a response.

For each IP address, both the raw IP and all domain names seen in logs are attempted as server name, to maximize the chances of triggering a response.

A crude cache system is implemented to make this work in a real network, where duplicate logs do not need to be checked repeatedly within a short timeframe.

By caching verdicts for IP + SNI combos, the mechanism is theoretically scalable even to networks that generate hundreds or thousands of HTTPS connections per second.

IP addresses of identified DoH endpoints are added to a list for a configurable period of time, and the list can be exported in one of three ways:

- **Text file**, continuously updated to add new entries and expire old entries. Best option for publication through a Webserver.

- **Python SimpleHTTPServer** hosting a text file. This is intended for testing and demonstration purposes only.

- **Palo Alto firewall API**. The script will use a provided API key to tag IP addresses on the Palo Alto firewall, for use in Dynamic Address Lists.

### Setup

Edit **config.txt** with the necessary information for your selected run mode (server/API/file) and run the script in the same folder as the config file. A sample ssl.log file is provided for testing.

### Scope

The idea for this script comes from Paul Vixie's [speech](https://youtu.be/ZxTdEEuyxHU?t=130) at EuroBSDcon 2019.

While it may work in a production network (use this at your own risk), it is mainly intended as a demonstration of what can be accomplished without the need for full TLS proxying, as well as a tool to allow crowd sourcing of lists of DoH resolvers. Hopefully this concept can be refined and become a viable security tool.

### Prerequisites

- pycurl
- [parsezeeklogs](https://pypi.org/project/parsezeeklogs/)
- A Zeek instance logging ssl traffic in TSV format

### TO DO:

- collect domain names from dns.log to use as server name candidates (could hypothetically be useful if clients start using Encrypted Client Hello)
- rate limiting for outbound checks (at the moment this can be accomplished by keeping the maximum thread count low with MAX_THREADS)
- add support for JSON Zeek logs


### License

This project is licensed under the [MIT License](https://github.com/o5edaxi/doh-hunter/blob/main/LICENSE).
