from fcntl import ioctl

import vmxcontrol

def clean_policy_item(item):
    if item[-1] == ',':
        return item[:-1]
    else:
        return item

class PolicyProcessor:
    def __init__(self, device_handle, polices):
        self.vmx_device_handle = device_handle
        self.log_on = False
        self.supported_policies = {
            'cr_write': self.process_cr_write,
            'msr_write': self.process_msr_write,
            'ept_protection': self.process_ept_protection,
        }
        self.policies = polices

    def parse_policy(self):
        for policy in self.policies:
            policy = [clean_policy_item(item) for item in policy]

            action = policy[0]

            assert action in self.supported_policies.keys(), \
                'Unrecognized policy' + str(action)

            self.supported_policies[action](policy[1:])

    def process_cr_write(self, options):
        supported_options = ['cr', 'mask', 'enable', 'allow']

        options = [item.replace(" ", "") for item in options]
        control = vmxcontrol.CrWriteControl()
        d_ctrl = control.asdict()
        d_ctrl['type'] = vmxcontrol.CONTROL_CR_WRITE
        #d_ctrl['enable'] = 1
        d_ctrl['allow'] = 1

        for option in options:
            fields = option.split('=')
            assert fields[0] in supported_options, \
            "Unknown option "  + fields[0]
            d_ctrl[fields[0]] = fields[1]

        control.setvar(d_ctrl)

        ioctl(self.vmx_device_handle, vmxcontrol.VMX_SWITCH_IOCTL_CONTROL_CR_WRITE, control)

    def process_msr_write(self, options):
        supported_options = ['msr', 'enable', 'allow']

        options = [item.replace(" ", "") for item in options]
        control = vmxcontrol.MsrWriteControl()
        d_ctrl = control.asdict()
        d_ctrl['type'] = vmxcontrol.CONTROL_MSR_WRITE
        #d_ctrl['enable'] = 1
        d_ctrl['allow'] = 0

        for option in options:
            fields = option.split('=')
            assert fields[0] in supported_options, \
            "Unknown option "  + fields[0]
            d_ctrl[fields[0]] = fields[1]

        control.setvar(d_ctrl)

        #with open(DEVICE_NAME, 'rb') as vmx_device_handle:
        ioctl(self.vmx_device_handle, vmxcontrol.VMX_SWITCH_IOCTL_CONTROL_MSR_WRITE, control)

    def process_ept_protection(self, options):
        supported_options = ['mem', 'prot']
        options = [item.replace(" ", "") for item in options]
        control = vmxcontrol.EptProtectionControl()
        d_ctrl = control.asdict()
        d_ctrl['type'] = vmxcontrol.CONTROL_EPT_PROT

        for option in options:
            fields = option.split('=')
            assert fields[0] in supported_options, "Unknown option " + fields[0]
            if fields[0] == 'mem':
                if fields[1] == 'kernel_code':
                    d_ctrl['mem_type'] = 1
                    d_ctrl['start_mem'] = 0
                    d_ctrl['end_mem'] = 0
                else:
                    d_ctrl['mem_type'] = 0
                    mem_values = [int(mem_value, 0) for mem_value in fields[1].split('-') ]
                    d_ctrl['start_mem'] = mem_values[0]
                    d_ctrl['end_mem'] = mem_values[1]
            else:
                d_ctrl[fields[0]] = fields[1]

        control.setvar(d_ctrl)
        ioctl(self.vmx_device_handle, vmxcontrol.VMX_SWITCH_IOCTL_CONTROL_EPT_PROT, control)
