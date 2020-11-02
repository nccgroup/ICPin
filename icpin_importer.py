import sys, re

read_regex = re.compile(r'^#\d+] .*?\+(.*): R \[\+(.*?) - .*?\) - (.*) bytes$')
write_regex = re.compile(r'^#\d+] .*?\+(.*): W \[\+(.*?)\] = (.*)  \(\d+ values\)')

class Gadget(object):

    def __init__(self, ip):
      self.ip=ip

    def __hash__(self):
        return self.ip

class ReadGadget(Gadget):

    def __init__(self, ip):
        super().__init__(ip)
        self.reads = {}

    def update(self, offset, size):
        assert offset not in self.reads
        self.reads[offset] = size

    def __repr__(self):
        return f'{self.ip:X} READ:'+'\n'.join(f'\t{offset:X} - {offset+size:X}' for offset, size in self.reads.items())

class WriteGadget(Gadget):

    def __init__(self, ip):
        super().__init__(ip)
        self.writes = {}

    def update(self, offset, values):
        self.writes.setdefault(offset, []).extend(values)

    def __repr__(self):
        ret = f'{self.ip:X} WRITE: {len(self.writes)} ' + ('values\n' if len(self.writes)>1 else 'value\n')
        ret += '\n'.join(f'\t{offset:X}: [' + ', '.join(f'{val:X}' for val in values) + ']' \
                    for offset, values in self.writes.items())
        return ret

class Importer(object):

  def __init__(self, filename):
    self.filename = filename

  def loadDB(self):
    gadgets = {}
    with open(self.filename, 'r') as f:
        for line in f.readlines():
            m = read_regex.match(line)
            if m:
                ip = int(m.group(1), 16)
                gadgets.setdefault(ip, ReadGadget(ip)).update(int(m.group(2), 16), int(m.group(3), 16))
            else:
                m = write_regex.match(line)
                if m:
                    ip = int(m.group(1), 16)
                    values = [int(v, 16) for v in m.group(3).split()]
                    gadgets.setdefault(ip, WriteGadget(ip)).update(int(m.group(2), 16), values)
    return gadgets

if __name__ == '__main__':
    imp = Importer(sys.argv[1])
    gadgets = imp.loadDB()
    for g in gadgets.values():
        print(g)
