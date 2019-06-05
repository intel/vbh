import ctypes
from enum import Enum

CONTROL_CR_WRITE = 0
CONTROL_CR_READ = 1
CONTROL_MSR_WRITE = 2
CONTROL_MSR_READ = 3
CONTROL_EPT_PROT = 4

VMX_SWITCH_CONTROL_SIZE = 24
VMX_SWITCH_IOCTL_MAGIC = 'k'

VMX_SWITCH_IOCTL_CONTROL_CR_WRITE = 0x40186b11
VMX_SWITCH_IOCTL_CONTROL_MSR_WRITE = 0x40186b13
VMX_SWITCH_IOCTL_CONTROL_EPT_PROT = 0x40206b16
VMX_SWITCH_IOCTL_CONTROL_STOP_LOG = 0x6b15
VMX_SWITCH_IOCTL_CONTROL_START_LOG = 0x6b14

class VmxEventType(Enum):
    ept_violation = 0
    msr_write = 1
    cr_write = 2
    xsetbv_modification = 3
    xcr_modification = 4
    breakpoint = 5
    vmcall = 6
    mtf_exit = 7

class VmxSwitchControl:
    def setvar(self, var):
        for key in var.keys():
            exec('self.{} = {}'.format(key, var[key]))

        return self

class MsrWriteControl(VmxSwitchControl, ctypes.Structure):
    _fields_ = [
        ('type', ctypes.c_long),
        ('enable', ctypes.c_byte),
        ('allow', ctypes.c_byte),
        ('msr', ctypes.c_int32)
    ]

    def asdict(self):
        return {'type': self.type, 'enable': self.enable, \
                'allow': self.allow, 'msr': self.msr}

class CrWriteControl(VmxSwitchControl, ctypes.Structure):
    _fields_ = [
        ('type', ctypes.c_long),
        ('enable', ctypes.c_byte),
        ('allow', ctypes.c_byte),
        ('cr', ctypes.c_int32),
        ('mask', ctypes.c_int32)
    ]

    def asdict(self):
        return {'type': self.type, 'enable': self.enable, \
                'allow': self.allow, 'cr': self.cr, 'mask': self.mask}

class EptProtectionControl(VmxSwitchControl, ctypes.Structure):
    _fields_ = [
        ('type', ctypes.c_long),
        ('start_mem', ctypes.c_long),
        ('end_mem', ctypes.c_long),
        ('prot', ctypes.c_int32),
        ('mem_type', ctypes.c_int16),
        ('allow', ctypes.c_int16)
    ]

    def asdict(self):
        return {'type': self.type, 'start_mem': self.start_mem, \
                'end_mem': self.end_mem, 'prot': self.prot, \
                'mem_type': self.mem_type, 'allow': self.allow}