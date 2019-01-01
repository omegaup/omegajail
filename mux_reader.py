#!/usr/bin/python3
"""Reader for stdio-mux output files."""

import argparse
import collections
import struct
import sys

Packet = collections.namedtuple('Packet',
                                ['stream_id', 'comm', 'timestamp', 'message'])


def _main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        'file',
        type=argparse.FileType('rb'),
        default=sys.stdin.buffer,
        help='The output file from stdio-mux')
    args = parser.parse_args()

    buffers = {}
    process_names = {}
    packets = []
    last_timestamp = 0
    while True:
        header = args.file.read(12)
        if not header:
            break
        stream_id, timestamp = struct.unpack('=IQ', header)
        message_length = timestamp & 0xFFFF
        timestamp >>= 16
        last_timestamp = max(last_timestamp, timestamp)
        message = args.file.read(message_length)

        if stream_id not in process_names:
            process_names[stream_id] = message.decode(errors='replace').strip()
            buffers[stream_id] = ''
            continue

        buffers[stream_id] += message.decode(errors='replace')
        while True:
            newline = buffers[stream_id].find('\n')
            if newline == -1:
                break
            packets.append(
                Packet(stream_id, process_names[stream_id], timestamp,
                       buffers[stream_id][:newline]))
            buffers[stream_id] = buffers[stream_id][newline + 1:]

    for stream_id, contents in buffers.items():
        if not contents:
            continue
        packets.append(
            Packet(stream_id, process_names[stream_id], last_timestamp,
                   contents))

    packets.sort(key=lambda packet: packet.timestamp)
    for packet in packets:
        color = '\033[0m'
        if packet.stream_id % 2 == 0:
            color = '\033[91m'
        print('%s[%s]: %s' % (color, packet.comm, packet.message))


if __name__ == '__main__':
    _main()
