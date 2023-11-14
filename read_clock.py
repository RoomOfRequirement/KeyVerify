import sys
import struct

with open(sys.argv[1], 'rb') as f:
    print(struct.unpack('d', f.read(8))[0])
