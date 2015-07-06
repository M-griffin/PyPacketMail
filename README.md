# PyPacketMail
Fidonet Mail Packet Processor for x/84 BBS

This project is still in early development.  It currently read and parser Type-2 Packet types, other types will be added in the future shuch as Type-2+ and Type-1 for backwards compatability.

This program interfaces with x/84's message and configuration system.  It will then process and handle the needed data conversions for importing and exporting Fidonet compitable messages between networked BBS's.


Completed:

- Parsing of packet bundles and mail packets
- INI configurations for Network address and message areas
- Initial import of messages

WIP:

- Sepearte database to hold Fidonet specifc klude lines
- Chaining origin and reply messages
- Message Exports
