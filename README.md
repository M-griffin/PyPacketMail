# PyPacketMail
Fidonet Mail Packet Processor for x/84 BBS

This project is still in early development.  It currently read and parser Type-2 Packet types, other types will be added in the future such as Type-2+ and Type-1 for backwards compatibility.

This program interfaces with x/84's message and configuration system.  It will then process and handle the needed data conversions for importing and exporting Fidonet compatible messages between networked BBS's.


Completed:

- Parsing of packet bundles and mail packets
- INI configurations for Network address and message areas
- Initial import of messages

WIP:

- Separate database to hold Fidonet specific kludge lines
- Chaining origin and reply messages id's
- Message Exports

Future Plans:

- Support for Private Netmail Messages
- Nodelist System/User Lookup for addressing private messages.
- Setup for running a Network Hub
- Files Requests and File Listings
