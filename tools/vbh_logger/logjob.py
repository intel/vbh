import threading
import os
import select
from fcntl import ioctl
import shutil

import vmxcontrol

LOG_BUFFER_SIZE = 128

#DEFAULT_LOG_DIR = '''./log/log_{}.dat'''

#LOG_FILE_NAME = '''log_{}.dat'''

blocked_read = False

next_file_num = 0

class LoggerExit(Exception):
    pass

class LogJob(threading.Thread):
    def __init__(self, vmx_device_h, log_dir, log_name):
        threading.Thread.__init__(self)
        self.log_dir = log_dir
        self.log_name = log_name
        self.shutdown_flag = threading.Event()
        self.log_buffer = bytearray(LOG_BUFFER_SIZE)
        self.total_read = 0
        self.vmx_device_handle = vmx_device_h
        self.log_on = False

    def save_read_buffer(self):
        global next_file_num
        #log_file_name = DEFAULT_LOG_DIR.format(next_file_num)
        log_file_name = os.path.join(self.log_dir, self.log_name.format(next_file_num))
        print(log_file_name)
        next_file_num += 1

        if not os.path.exists(os.path.dirname(log_file_name)):
            os.makedirs(os.path.dirname(log_file_name))

        with open(log_file_name, 'bw') as log_f:
            log_f.write(self.log_buffer[:self.total_read])

    def blocked_read(self):
        while not self.shutdown_flag.is_set():
            while True:
                mv = memoryview(self.log_buffer)[self.total_read:]
                bytes_read = self.vmx_device_handle.readinto(mv)
                self.total_read += bytes_read

                # TODO: Fix error code
                if self.total_read > 0 and bytes_read == 0:
                    self.save_read_buffer()
                    self.log_buffer[:] = b'0' * len(self.log_buffer)
                    self.total_read = 0

                # TODO: Fix error code
                if bytes_read == -1 and self.log_on == False:
                    break

        if self.total_read > 0:
            self.save_read_buffer()

    def non_blocked_read(self):
        fd_to_handler = {self.vmx_device_handle.fileno(): self.vmx_device_handle}

        read_only = select.POLLIN | select.POLLRDNORM
        poller = select.poll()
        poller.register(self.vmx_device_handle, read_only)

        while not self.shutdown_flag.is_set():
            while True:
                mv = memoryview(self.log_buffer)[self.total_read:]
                events = poller.poll()

                for fd, flag in events:
                    if flag & read_only:
                        bytes_read = fd_to_handler[fd].readinto(mv)
                        self.total_read += bytes_read
                        print('log buf: bytes_read=%d, total_read = %d' % (bytes_read, self.total_read))

                        if self.total_read > 0 and bytes_read == 0:
                            self.save_read_buffer()
                            self.log_buffer[:] = b'0' * len(self.log_buffer)
                            self.total_read = 0

                if not self.log_on:
                    break

        if self.total_read > 0:
            self.save_read_buffer()

    def run(self):
        print('Logging job #%s started' % self.ident)

        if blocked_read:
            self.blocked_read()
        else:
            self.non_blocked_read()

        print('Logging job #%s stopped.' % self.ident)

    def stop_log(self, signum, frame):
        print('Caught signal %d' % signum)

        ioctl(self.vmx_device_handle, vmxcontrol.VMX_SWITCH_IOCTL_CONTROL_STOP_LOG, 0)

        self.log_on = False

        raise LoggerExit

    def start_log(self):
        ret = ioctl(self.vmx_device_handle, vmxcontrol.VMX_SWITCH_IOCTL_CONTROL_START_LOG, 0)

        if ret == 0:
            if os.path.isdir(self.log_dir):
                shutil.rmtree(self.log_dir)

            self.log_on = True

        return self.log_on