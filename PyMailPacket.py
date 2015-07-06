#!/usr/bin/env python2.7
""" PyMailPacket for x/84, http://github.com/jquast/x84
    (c) 2015 Michael Griffin <mrmisticismo@hotmail.com>
    http://github.com/m-griffin/PyMailPacket

    This is a FidoNet Echomail Scanner / Tosser for x84 bbs.
    This will mimic the basic functionality of Crashmail for
    Reading and Writing mail packets.

    *** Sample INI Section to be added to DEFAULT.INI in X84

    # Setup for PyPacket Mail {Fidonet Tosser/Scanner}
    [mailpacket]
    inbound = /home/pi/Desktop/PyPacketMail/inbound
    outbound = /home/pi/Desktop/PyPacketMail/outbound
    pack = /home/pi/Desktop/PyPacketMail/pack
    unpack = /home/pi/Desktop/PyPacketMail/unpack
    bad = /home/pi/Desktop/PyPacketMail/bad
    archive = /home/pi/Desktop/PyPacketMail/archive

    # Fido Type Network Domain names, seperate with commas.
    [fido_networks]
    network_tags = agoranet, fidonet

    # Network Specific Addresses and Area -> Tag Translations.
    [agoranet]
    node_address = 46:1/140
    export_address = 46:1/100
    areas = agn_gen: general, agn_ads: bbs_ads, agn_bbs: bbs_discussion, agn_art: art, agn_dev: development,
            agn_nix: unix_linux, agn_hub: hub_stats, agn_l46: league46, agn_tst: testing, agn_sys: sysop_area

    # Network Specific Addresses and Area -> Tag Translations.
    [fidonet]
    node_address = 1:154/140
    export_address = 1:154/10
    areas = fdn_ent: enthral_bbs

"""

__author__ = "Michael Griffin"
__copyright__ = "Copyright 2015"
__credits__ = "Jeff Quast"
__license__ = "MIT"
__version__ = "1.0.0"
__status__ = "Prototype"


import collections
import datetime
import zipfile
import struct
import glob
import os

# Reading Binary Packet Formats
from ctypes import LittleEndianStructure, Union, c_uint8

# x84 specific
from x84.bbs.ini import init, get_ini
from x84.cmdline import parse_args

# WIP
INDEXDB = 'pymail_index'

# Read in default .x84 INI File.
init(*parse_args())


class FidonetConfiguration():
    # Holds configuration values from x84 Default.ini
    # also builds up lists of areas per network and
    # their data -> tag translatons
    def __init__(self):
        self.__network_list = []     # List of Fido Networks
        self.__node_address = {}     # Your Address
        self.__export_address = {}   # Your Network Hub's Address
        self.__network_areas = {}    # Message Areas by network
        self.__inbound_folder = None
        self.__unpack_folder = None
        self.read_configuration()    # Load All INI settings on startup.

    def add_network(self):
        # Everything is built from the initial network address
        self.__network_list = \
            get_ini(section='fido_networks', key='network_tags', split=True)

    def add_node_address(self):
        # Node Addresses per network
        if self.is_network_empty is False:
            for net in self.__network_list:
                # Loop network list and get network section.
                self.__node_address[net] = \
                    get_ini(section=net, key='node_address', split=True)

    def add_export_address(self):
        # Export {mail hub} addresses per network
        if self.is_network_empty is False:
            for net in self.__network_list:
                # Loop network list and get network section.
                self.__export_address[net] = \
                    get_ini(section=net, key='export_address', split=True)

    def add_network_areas(self):
        # key value area to tag translations per network
        if self.is_network_empty is False:
            for net in self.__network_list:
                # Loop network list and get network section.
                self.__network_areas[net] = \
                    get_ini(section=net, key='areas', split=True)

    @property
    def is_network_empty(self):
        if bool(self.__network_list and True):
            return False
        return True

    @property
    def inbound_folder(self):
        return self.__inbound_folder

    @property
    def unpack_folder(self):
        return self.__unpack_folder

    def check_network_address(self, address):
        # verify node address, return network name
        for key, val in self.__node_address.items():
            if address in ''.join(val):
                return '{network}'.format(network=key)
        return None

    def get_tag(self, network_name, network_area):
        # transpose area to tag name
        # seperate string value into k, v dist.
        if self.is_network_empty is False:
            for area in self.__network_areas[network_name]:
                k, v = area.split(': ')
                if network_area in k:
                    return v
        return None

    def read_configuration(self):
        # Working Folders pull from .x84 Default INI
        self.__inbound_folder = ''.join(get_ini(section='mailpacket', key='inbound', split=True))
        self.__unpack_folder = ''.join(get_ini(section='mailpacket', key='unpack', split=True))

        # read .x84 default.ini file for network info
        # build dicts for all networks and their associations
        self.add_network()
        print 'network_list: ' + ', '.join(str(x) for x in self.__network_list)

        self.add_node_address()
        for key, val in self.__node_address.items():
            print 'node_address: {key}, {value}'.format(key=key, value=val)

        self.add_export_address()
        for key, val in self.__export_address.items():
            print 'export_address: {key}, {value}'.format(key=key, value=val)

        self.add_network_areas()
        for key, val in self.__network_areas.items():
            print 'network_areas: {key}, {value}'.format(key=key, value=val)

print ''

# Parse and Setup Fido-net addresses and areas
cfg = FidonetConfiguration()

print ''
print 'is network empty: {bool}'.format(bool=cfg.is_network_empty)
print 'inbound_folder: {name}'.format(name=cfg.inbound_folder)
print 'unpack_folder : {name}'.format(name=cfg.unpack_folder)
print ''

# Make sure we have at least one network setup
assert cfg.is_network_empty is False

# Make sure the Inbound directory is valid
assert os.path.isdir(cfg.inbound_folder)

# Check the Packet Folder.
assert os.path.isdir(cfg.unpack_folder)

# Handle count of Areas Processed
area_count = collections.defaultdict(int)

# Fido Packet 2 Structure
_struct_packet_header_fields = [
    # Structure Size 58
    ('H', 'origin_node'),
    ('H', 'destination_node'),
    ('H', 'year'),
    ('H', 'month'),
    ('H', 'day'),
    ('H', 'hour'),
    ('H', 'minute'),
    ('H', 'second'),
    ('H', 'baud'),
    ('H', 'packet_type'),
    ('H', 'origin_network'),
    ('H', 'destination_network'),
    ('B', 'prod_code_low'),
    ('B', 'revision_major'),
    ('8s', 'password'),
    ('H', 'origin_zone'),
    ('H', 'destination_zone'),
    ('H', 'aux_network'),
    ('H', 'capWordA'),
    ('B', 'prod_code_hi'),
    ('B', 'revision_minor'),
    ('H', 'capWordB'),
    ('H', 'origin_zone2'),
    ('H', 'destination_zone2'),
    ('H', 'origin_point'),
    ('H', 'destination_point'),
    ('L', 'prod_data')
]

_struct_fidonet_packet = '<{0}'.format(
    ''.join(struct_val for struct_val, _ in _struct_packet_header_fields))

FidonetPacketHeader = collections.namedtuple(
    'FidonetPacketHeader', [field_name for _, field_name in _struct_packet_header_fields])


class FlagBits(LittleEndianStructure):
    # Captures the 1st Byte Set of Bit Flags in the Message Header
    _fields_ = [
        ('private',      c_uint8, 1),  # asByte & 1
        ('crash',        c_uint8, 1),  # asByte & 2
        ('received',     c_uint8, 1),  # asByte & 4
        ('sent',         c_uint8, 1),  # asByte & 8
        ('file_attach',  c_uint8, 1),  # asByte & 16
        ('in_transit',   c_uint8, 1),  # asByte & 32
        ('orphan',       c_uint8, 1),  # asByte & 64
        ('kill_sent',    c_uint8, 1),  # asByte & 128
    ]

    def get_dict(self):
        # return ordered fields of bits
        return collections.OrderedDict((f, getattr(self, f)) for f, v, i in self._fields_)


class FlagBits2(LittleEndianStructure):
    # Captures the 2nd Byte Set of Bit Flags in the Message Header
    _fields_ = [
        ('local',        c_uint8, 1),  # asByte & 256
        ('hold',         c_uint8, 1),  # asByte & 512
        ('unused',       c_uint8, 1),  # asByte & 1024
        ('file_request', c_uint8, 1),  # asByte & 2048
        ('want_receipt', c_uint8, 1),  # asByte & 4096
        ('is_receipt',   c_uint8, 1),  # asByte & 8192
        ('audit',        c_uint8, 1),  # asByte & 16384
        ('file_update',  c_uint8, 1),  # asByte & 32768
    ]

    def get_dict(self):
        # return ordered fields of bits
        return collections.OrderedDict((f, getattr(self, f)) for f, v, i in self._fields_)


class Flags(Union):
    # Union to set the In_Value flips the appropriate bits flags
    # in_value can also be used to get the value of all set flags
    _fields_ = [('bit', FlagBits),
                ('in_value', c_uint8)]


class Flags2(Union):
    # Union to set the In_Value flips the appropriate bits flags
    # in_value can also be used to get the value of all set flags
    _fields_ = [('bit', FlagBits2),
                ('in_value', c_uint8)]


class SetFlags():
    # Class to handle Bit Flags for Message Attributes
    field = None
    field2 = None

    def __init__(self, field, field2):
        # get flags from message header
        """

        :rtype : None
        """
        self.field = field
        self.field2 = field2
        self.set_flags()

    def set_flags(self):
        attributes = Flags()
        attributes.in_value = self.field

        attributes2 = Flags2()
        attributes2.in_value = self.field2

        # Test Print out first 8 Bits
        # print attributes.bit.get_dict()

        # Test Print out Second 8 Bits
        # print attributes2.bit.get_dict()

# Fido Message Header Structure
_struct_message_header_fields = [
    # Structure Size 14
    ('H', 'message_type'),
    ('H', 'origin_node'),
    ('H', 'destination_node'),
    ('H', 'origin_network'),
    ('H', 'destination_network'),
    ('B', 'attributes_flags1'),
    ('B', 'attributes_flags2'),
    ('H', 'cost'),
]
_struct_fidonet_message_header = '<{0}'.format(
    ''.join(struct_val for struct_val, _ in _struct_message_header_fields))

FidonetMessageHeader = collections.namedtuple(
    'FidonetMessageHeader', [field_name for _, field_name in _struct_message_header_fields])


def read_cstring(file_object, offset):
    # Function to read text up to null terminator
    new_string = ""
    # jump to offset.
    assert isinstance(offset, object)
    file_object.seek(offset)
    while True:
        # read the file object
        byte = file_object.read(1)
        if not byte:
            break
        if byte in '\x00':
            # Break on Null Terminated
            break

        new_string += str(byte)

    return new_string


def read_message_text(file_object, offset):
    # Function to read message text up to null terminator
    assert isinstance(offset, object)
    file_object.seek(offset)

    message_string = ""
    for chunk in iter(lambda: file_object.read(1), ''):
        if chunk in '\x00':
            break

        message_string += chunk
    return message_string


def track_area(area):
    """
    :rtype : None
    """
    if area_count[area] is not None:
        area_count[area] += 1
    else:
        area_count[area] = 1


def print_area_count():
    # Print out Counts of messages per area
    print ''
    total_messages = 0
    total_areas = 0
    for area in area_count:
        print u'Area: {0} -> Total Messages: {1}'.format(
            area, area_count[area])
        total_messages += area_count[area]
        total_areas += 1

    # hard coded for now, this will be setup with dupe checking
    total_messages_imported = total_messages

    print ''
    print 'Areas: {0} -> Messages: {1} -> Imported -> {2}.'.format(
        total_areas, total_messages, total_messages_imported)


def get_msg_last_read(area=None):
    # return last read pointer for current area.
    from x84.bbs import DBProxy
    db_index = DBProxy(INDEXDB)
    if area:
        return db_index.get(area, set())
    # flatten list of [set(1, 2), set(3, 4)] to set(1, 2, 3, 4)
    return set([_idx for indices in db_index.values() for _idx in indices])


class MsgIndex(object):
    # Holds the Exported Message Index of new messages
    # for outbound mail packets.
    def __init__(self, area_name, msg_last_read):
        self.area = area_name
        self.pointer = msg_last_read
        self.index = None

    def set_index(self):
        # persist message index record to database
        from x84.bbs import DBProxy
        new = self.index is None

        with DBProxy(INDEXDB, use_session=False) as db_index:
            if new:
                self.index = max(map(int, db_index.keys()) or [-1]) + 1
                new = True
            db_index['%d' % (self.index,)] = self


class Message(object):
    # Message Object that will be pasted into.
    def __init__(self):
        """
        :rtype : None
        :type self: str
        """
        self.date_time = None
        self.user_to = None
        self.user_from = None
        self.subject = None
        self.area = None
        self.tag_line = None
        self.origin_line = None
        self.kludge_lines = collections.OrderedDict()
        self.seen_by = []
        self.raw_data = None
        self.message_header = None
        self.packet_header = None
        self.packet_address = None
        self.network = None
        # Clean Message Text, Split with CR, remove any LF!
        self.message_lines = None

        # Initial method when we enter the class.
        #self.parse_lines()

    def import_messages(self):
        from x84.bbs.msgbase import Msg
        # hook into x84 and write message to default database and
        # keep separate database for fido specific fields.

        # 'author': msg.author,
        # 'subject': msg.subject,
        # 'recipient': msg.recipient,
        # 'parent': parent,
        # 'tags': [tag for tag in msg.tags if tag != network['name']],
        # 'body': u''.join((msg.body, format_origin_line())),
        # 'ctime': to_utctime(msg.ctime)

        store_msg = Msg()
        store_msg.recipient = unicode(self.user_to, 'CP437')
        store_msg.author = unicode(self.user_from, 'CP437')
        store_msg.subject = unicode(self.subject, 'CP437')

        # Add Check here for Private Netmail messages

        # Convert from CP437 for high ascii, later on read CHRS kludge for origin character set
        store_msg.body = unicode('\r'.join(self.message_lines).replace('\x9d', ''), 'CP437')

        # If area is a normal public echo, default is public
        store_msg.tags.add(u''.join('public'))

        # Change to Network Name ie Agoranet
        store_msg.tags.add(u''.join(self.network))

        # Translate the area to the tag description.
        # eg.. AGN_GEN -> general
        area_tag = cfg.get_tag(self.network, self.area)

        print 'Area Tag: ' + area_tag
        if area_tag is not None:
            store_msg.tags.add(u''.join(area_tag))

        # In testing
        # if area is not a public echo, add to sysop group tag
        # store_msg.tags.add(u''.join('sysop'))

        # Convert Packet String to Date Time format.
        # We should also get and check UTZ kludge line!  Lateron for offset / Timezone.
        # 26 Feb 15  18:04:00
        date_object = datetime.datetime.strptime(self.date_time, '%d %b %y %H:%M:%S')

        print date_object

        # do not save this message to network, we already received
        # it from the network, set send_net=False
        # Also avoid sending over X84 NET
        store_msg.save(send_net=False, ctime=date_object)
        del store_msg

    def add_kludge(self, line):
        # Separates Kludge Lines into An Array of Fields
        key, value = line.split(None, 1)
        key = key[1:]

        if key in self.kludge_lines:
            assert isinstance(value, object)
            self.kludge_lines[key].append(value)
        else:
            self.kludge_lines[key] = [value]

    def parse_lines(self):
        # Breaks up the message data into fields
        stage = 1
        message_body = []

        # Setup Message Lines by breaking up raw data
        self.message_lines = [x.strip('\n') for x in self.raw_data.split('\r')]

        for line in self.message_lines:

            if len(line) == 0:
                # Empty Lines are Newlines
                message_body.append('')

            elif stage == 1:
                # Start and Middle of Message Text
                if line.startswith('AREA:'):
                    # grab description config file and translate area name
                    self.area = line.split(':')[1].lower()
                    # print 'Area : ' + self.area

                    # Add count for area
                    track_area(self.area)

                elif line.startswith('\x01'):
                    self.add_kludge(line.strip())

                elif line.startswith('--- '):
                    # Tracking Tag Lines might be a little much!
                    self.tag_line = line
                    # Leave Tag Line in message text
                    message_body.append(line)

                elif 'Origin:' in line[2:10]:
                    # note some systems like Synchronet doesn't use * for origin prefix!!
                    # need to put range in for this!! +2, 10
                    self.origin_line = line
                    # Leave Tag Line in message text
                    message_body.append(line)
                    stage = 2

                # not official, just preference to remove this invalid data record.
                elif line.startswith('\x1ASAUCE00'):
                    # skip bad characters or records in messages
                    continue

                elif line.endswith('\x04'):
                    # Skip SAUCE record end lines!, shouldn't be posted.
                    # bad characters
                    continue

                else:
                    message_body.append(line)

            elif stage == 2:
                # Stage 2 After Origin Line Only
                if line.startswith('\x01'):
                    self.add_kludge(line)

                elif line.startswith('SEEN-BY:'):
                    self.seen_by.append(line)

                else:
                    raise ValueError('Unexpected: %s' % line)

        self.message_lines = message_body

        # Import messages to x84
        self.import_messages()

    def __str__(self):
        # Check this, should swap \r ? -MF
        """
        :rtype : str
        """
        return '\n'.join(self.message_lines)

    def serialize(self):
        # Build The Message for Writing out to Packet
        lines = []

        if self.area:
            lines.append('AREA:%s' % self.area)

        for key, kludge_value in self.kludge_lines.items():
            for value in kludge_value:
                # Check if these needs \r at end of line!!
                lines.append('\x01%s %s' % (key, value))

        lines.extend(self.message_lines)

        if self.origin_line:
            lines.append(self.origin_line)

        lines.extend(self.seen_by)


class ParsePackets(object):

    area_count_dict = {}

    def __init__(self, packet_processing):
        # Inbound or Outbound processing.
        """

        :type packet_processing: str
        """
        _packet_processing = packet_processing
        if _packet_processing in 'read':
            process_inbound()
            print_area_count()


def process_inbound():
    # Process all packets waiting in the inbound_folder
    """

    :rtype : none
    """
    message_count = 0

    for file_path_zip in glob.glob(os.path.join(cfg.inbound_folder, u'*.*')):
        # Uncompress packet bundles, then loop to read packet/message headers/messages
        try:
            # unzip a clean bundle
            with zipfile.ZipFile(file_path_zip) as zip_obj:
                print u'Uncompress Bundle: ' + os.path.basename(file_path_zip)
                zip_obj.extractall(cfg.unpack_folder)

            # Loop and process all packets
            for file_name in os.listdir(cfg.unpack_folder):
                # Parse Each Packet for the Header first.
                print u'Parsing Mail Packet: ' + file_name

                # Open then Parse Each Packet
                fido_object = open(os.path.join(cfg.unpack_folder, file_name), 'rb')

                try:
                    # make Sure we don't read past the end of the file!
                    packet_header_read = fido_object.read()[:58]
                except EOFError:
                    # move to next packet if were at the end.
                    break

                if not packet_header_read:
                    # move to next packet, log error here
                    print u'Error: unable to read packet header: ' + file_name
                    break

                # Make sure we have correct size! Otherwise were done.
                # print 'packet_header_read len: ' + str(len(packet_header_read))
                if len(packet_header_read) < 58:
                    # End of File can have (2) Bytes, catch this.
                    break

                # Read the Packet Header
                fido_header = FidonetPacketHeader(
                    *struct.unpack(_struct_fidonet_packet, packet_header_read))

                # Test the packet header
                if fido_header.packet_type != 2:
                    print u'Error: fido packet not Type-2: ' + file_name
                    break

                # Validate packet is addressed to this system
                # Add 5D addresses? have @domain like @agoranet
                if fido_header.destination_point != 0:
                    # 4D address
                    packet_address = '{zone}:{net}/{node}.{point}'.format(
                        zone=fido_header.destination_zone, net=fido_header.destination_network,
                        node=fido_header.destination_node, point=fido_header.destination_point)
                else:
                    # 3D Address no point.
                    packet_address = '{zone}:{net}/{node}'.format(
                        zone=fido_header.destination_zone, net=fido_header.destination_network,
                        node=fido_header.destination_node)

                # If Address is not in our network, skip to next packet.
                current_network = cfg.check_network_address(packet_address)
                if current_network is None:
                    print u'Error: packet not addressed to your node: {packet}, '\
                        .format(packet=packet_address)
                    break

                print u'Packet Received for: {network} -> {packet}'\
                    .format(network=current_network, packet=packet_address)

                assert isinstance(fido_header, object)
                # print fido_header

                offset = struct.calcsize(_struct_fidonet_packet)
                message_count = 0
                while True:

                    # Reset Position to right after Fido Header
                    fido_object.seek(offset)

                    # Try to parse the message header
                    try:
                        # make Sure we don't read past the end of the file!
                        message_header_read = fido_object.read()[:14]
                    except EOFError:
                        # move to next packet if were at the end.
                        break

                    if not message_header_read:
                        # move to next packet, log error here
                        break

                    # Make sure we have correct size! Otherwise were done.
                    # print 'message_header_read len: ' + str(len(message_header_read))
                    if len(message_header_read) <= 2:
                        # End of File can have (2) Bytes, catch this.
                        break
                    elif len(message_header_read) < 14:
                        # Read was short!
                        print u'Error: unable to read message header: ' + file_name
                        break

                    # Read the Message Header
                    fido_message_header = FidonetMessageHeader(
                        *struct.unpack(_struct_fidonet_message_header, message_header_read))

                    assert isinstance(fido_message_header, object)

                    SetFlags(fido_message_header.attributes_flags1,
                             fido_message_header.attributes_flags2)

                    # Update The Offset
                    offset += struct.calcsize(_struct_fidonet_message_header)

                    # Next move back to the next position
                    """ Next we need to parse For '\x00' terminated strings.
                    ('20s', 'dateTime'),
                    ('36s', 'toUsername'),
                    ('36s', 'fromUsername'),
                    ('72s', 'subject')
                    """

                    # Use cleaner way to keep track of offset!!
                    date_time_string = read_cstring(fido_object, offset)
                    offset += len(date_time_string) + 1

                    username_to = read_cstring(fido_object, offset)
                    offset += len(username_to) + 1

                    username_from = read_cstring(fido_object, offset)
                    offset += len(username_from) + 1

                    subject_string = read_cstring(fido_object, offset)
                    offset += len(subject_string) + 1

                    # We now read the entire message up to null terminator
                    message_string = read_message_text(fido_object, offset)
                    offset += len(message_string) + 1

                    # Breaks up the message and separates out kludge lines from text.
                    # print Message(message_string, username_to, username_from, subject_string)
                    current_message = Message()

                    current_message.date_time = date_time_string
                    current_message.user_to = username_to
                    current_message.user_from = username_from
                    current_message.subject = subject_string
                    current_message.raw_data = message_string

                    # Packet Headers will check for source / destination address
                    # mainly dupe checking
                    current_message.packet_header = fido_header
                    # Message Headers will be checked for Import/Export flags etc.
                    current_message.message_header = fido_message_header

                    # Populated the Current Network and Address.
                    current_message.network = current_network
                    current_message.packet_address = packet_address

                    # First Parse the Raw Data into Message Lines and
                    # break out Kludge lines from text
                    # if No errors then Import Message to x84
                    current_message.parse_lines()
                    message_count += 1

                # Cleanup for next run
                fido_object.close()
                print u'    Messages This Packet -> ' + str(message_count)

        finally:
            # Clear the unpack_folder here later on, leave for testing, just overwrites!
            print u'End of Bundle'
            print ''

            # Clear out any packets before running next bundle
            clear_files = glob.glob(os.path.join(cfg.unpack_folder, u'*.*'))
            for f in clear_files:
                os.remove(f)


class TossMessages(ParsePackets):
    # handle incoming messages
    def __init__(self):
        # Inbound or Outbound processing.
        """

        :rtype : none
        """

        _packet_processing = 'read'
        super(TossMessages, self).__init__(_packet_processing)

        
class ScanMessages(ParsePackets):
    # handle outgoing messages
    def __init__(self):
        # Inbound or Outbound processing.
        """

        :rtype : none
        """
        _packet_processing = 'write'
        super(ScanMessages, self).__init__(_packet_processing)
        

def main(background_daemon=False):
    # Scan for Incoming Message and Import them
    if not background_daemon:
        TossMessages()

if __name__ == '__main__':
    # x84 init for CFG w/ x84.cmdline
    # Keep this in main program so we can read get_ini properly!
    # init(*parse_args())

    # do not execute message polling as a background thread.
    main(background_daemon=False)
