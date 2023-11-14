import sys
import struct

with open(sys.argv[1], 'wb') as f:
    f.write(struct.pack('d', 0.0))
