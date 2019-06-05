import glob
import os
import mmap
import struct
from vmxcontrol import VmxEventType

class VlScript:
    def __init__(self,logdir, log_suffix):
        self.LogDirectory = logdir
        self.raw_log_suffix = '*.' + log_suffix
        #self.LogFile = self.LogDirectory + 'log.txt'
        self.LogFile = 'log.txt'
        self.MetaDataSize = 16
        self.MetaDataFields = ('vcpu', 'event_type', 'payload_size')
        self.EventMsrFields = ('msr', 'padding', 'old_value', 'new_value')
        self.EventEptViolationFields = ('gla', 'gpa', 'g_rip', 'g_rsp', 'mode', 'padding')

    @staticmethod
    def memory_map(filename, access = mmap.ACCESS_READ):
        size = os.path.getsize(filename)
        fd = os.open(filename, os.O_RDONLY)

        return mmap.mmap(fd, size, access=access)

    def script(self):
        os.chdir(self.LogDirectory) # change directory

        if os.path.isfile(self.LogFile):
            os.remove(self.LogFile)

        log_entries=[]

        for blogfile in glob.glob(self.raw_log_suffix):
            start = 0

            mlog = self.memory_map(blogfile)
            while start < mlog.size():
                end = start + self.MetaDataSize
                #print('start={}, end={}, size={}'.format(start, end, mlog.size()))
                meta_data = struct.unpack('IIQ', mlog[start:end])
                header = dict(zip(self.MetaDataFields, meta_data))
                #print('header:{}'.format(header))

                start += self.MetaDataSize
                end = start + header['payload_size']

                if header['event_type'] == VmxEventType.msr_write.value:
                    value = struct.unpack('IIQQ', mlog[start:end])
                    data = dict(zip(self.EventMsrFields, value))
                    #print('data:{}'.format(data))
                    log_entry =  "{}: vcpu={}, old_value={}, new_vaule={}\n".format(VmxEventType.msr_write.name, \
                                                                   header['vcpu'], \
                                                                   data['old_value'], \
                                                                   data['new_value'])
                    #print(log_entry)

                    log_entries.append(log_entry)

                    start = end
                elif header['event_type'] == VmxEventType.ept_violation.value:
                    value = struct.unpack('QQQQII', mlog[start:end])
                    data = dict(zip(self.EventEptViolationFields, value))
                    print('data:{}'.format(data))
                    log_entry = "{}: vcpu={}, gla=0x{:x}, gpa=0x{:x}, grip=0x{:x}, grsp=0x{:x}\n".format(VmxEventType.ept_violation.name, \
                                header['vcpu'], \
                                data['gla'], \
                                data['gpa'], \
                                data['g_rip'], \
                                data['g_rsp'])
                    log_entries.append(log_entry)
                    start = end

            mlog.close()

        if log_entries:
            with open(self.LogFile, 'a+') as logfile:
                logfile.writelines(log_entries)