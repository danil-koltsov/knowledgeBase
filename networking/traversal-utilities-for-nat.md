# TRAVERSAL UTILITIES FOR NAT

**1** **Danil Koltsov**

**2** **Ivan Parkhomenko**

PhD in Technical Sciences, Associate Professor Department of Cybersecurity and Information Protection

_1,2_ _Taras Shevchenko National University of Kyiv\*\*._ _60 Volodymyrska Street, City of Kyiv, Ukraine, 01033_

### Abstract

The question of why you can't connect to the server via NAT is considered. Requirements to traversal NAT. Options for this to be done.

### Keywords

Traversal NAT, P2P applications, STUN, TURN, ICE.

## 1.  INTRODUCTION

A big problem for many applications is the inability to establish a connection at all. This is especially true for P2P applications such as VoIP, messengers, and file sharing, which often need to act as both a client and a server to provide two-way direct communication.

If NAT is available, the internal client does not know about its public IP address. It knows its internal IP address, and NAT devices overwrite the output port and address in each TCP/UDP packet and the output IP address inside the IP packet. However, if the client transmits its private IP address a part of its application data to an equal external environment outside its private network, then the connection will fail.

Therefore, if you want to share peer-to-peer code outside your private network, the application must first detect its public IP address. Another packet that arrives at the public IP address of the Nat device must also have a destination port and an entry in the NAT table that can translate it to the internal IP address of the destination host and a tuple of ports.

To eliminate this discrepancy in NAT, there are methods for bypassing STUN, TURN, and ICE, which are used to establish end-to-end communication between peer members on both sides.

## 2.  SESSION TRAVERSAL UTILITIES FOR NAT \(RFC 5389\)

Session bypass utilities for NAT STUN \(RFC 5389\) is a protocol that allows the host application to detect the presence of a network address translator on the network and, if available, get a dedicated public IP address and a tuple port for the current connection. To do this, the protocol requires the help of a well-known third-party stun server, which must be located on a public network.

```text
+----------------------+          +-------+      public IP, PORT?       +--------+
|                      |--------->|       |---------------------------->|        |
|  192.168.31.23:3212  |          |  NAT  |                             |  STUN  |
|                      |<---------|       |<----------------------------|        |
+----------------------+          +-------+      93.72.33.221:32123     +--------+
```

**Figure 1** – STUN request for public IP and Port

Assuming that the IP address of the stun server is known \(via DNS detection or at a manually specified address\), the application first sends a request to bind to the stun server. In its turn, the stun server responds with a response that contains the public IP address and client port that is visible from the public network.

This process has several problems.

· The app detects its public IP and port packet, and can then use this information as part of its app data when communicating with its members.

· An outgoing binding request to the stun server sets NAT routing records along the path, so that incoming packets arriving at the public IP address and Port tuple can now find their way back to the host application on the internal network.

· The STUN protocol defines a simple ping saving mechanism to avoid waiting times for NAT routing records.

With this mechanism, when two peer-to-peer partners want to communicate with each other, they first send binding requests to their respective STUN servers, and after both parties successfully respond, they can use the established public tuples of IP and ports to exchange data.

## 3.  TRAVERSAL USING RELAYS AROUND NAT \(RFC 5766\)

However, in practice, STUN is not sufficient to work with all NAT topologies and network configurations. In some cases, UDP may be blocked by a firewall or other network device - a common scenario for many corporate networks. To solve this problem when the STUN fails, we can use the relay bypass protocol around Nat \(TURN\) \(RFC 5766\) as a backup option that can work over UDP and switch to TCP if all else fails.

The key word in TURN is, of course,"relays". The protocol relies on the availability and availability of a public repeater to transmit data between members.

```text
+------------------+   +-------+    +--------+    +-------+   +------------------+
|                  |-->|       |--->|        |--->|       |-->|                  |
|192.168.31.23:3212|   |  NAT  |    |  TURN  |    |  NAT  |   |192.168.31.13:2233|
|                  |<--|       |<---|        |<---|       |<--|                  |
+------------------+   +-------+    +--------+    +-------+   +------------------+
Figure 2 – TURN
```

* Both clients start their connections by sending a distribution request to the same turn server, followed by permission approval.
* Once reconciliation is complete, both peers communicate by sending their data to the TURN server, which then passes it to another peer.

## 4.  INTERACTIVE CONNECTIVITY ESTABLISHMENT \(RFC 5245\)

ICE \(RFC 5245\) is a protocol and set of methods that aim to establish the most efficient tunnel between participants, provide direct connection where possible, use stun negotiations where necessary, and finally return to TURN if all else fails.

```text
                                    +--------+
                          +-------->|        |---------+
                          |         |  TURN  |         |
                          |  +------|        |<-----+  |
                          |  |      +--------+      |  |
                          |  V                      |  V
+------------------+   +-------+                  +-------+   +------------------+
|                  |-->|       |----------------->|       |-->|                  |
|192.168.31.23:3212|   |  NAT  |                  |  NAT  |   |192.168.31.13:2233|
|                  |<--|       |<-----------------|       |<--|                  |
+------------------+   +-------+                  +-------+   +------------------+
                          ^ |                        ^ |
                          | V                        | V
                       +--------+                +--------+
                       |        |                |        |
                       |  STUN  |                |  STUN  |
                       |        |                |        |
                       +--------+                +--------+
```

**Figure** **3** – ICE

## 5.  REFERENCES

Recommendations \[1, 2, 3\]

1. RFC 5389 Session Traversal Utilities for NAT 
2. RFC 5766 Traversal Using Relays around NAT
3. RFC 5245 Interactive Connectivity Establishment

