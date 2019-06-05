import fcntl
import time
import signal
from pprint import pprint

import logjob
import policyprocessor
import cmdparser
import vlscript

DEFAULT_LOG_DIR = '''./log/'''

LOG_FILE_SUFFIX = 'dat'

LOG_FILE_NAME = '''log_{}.dat'''

DEVICE_NAME='/dev/vmx_switch'

SingletonFP = None

def singleton_app():
    global SingletonFP

    pid_file = 'program.pid'

    SingletonFP = open(pid_file, 'w')

    try:
        fcntl.flock(SingletonFP, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, IOError):
        print('Program is already running.\n')
        quit()

def main():

    vmx_device_handle = open(DEVICE_NAME, 'rb', buffering=0)

    log_on = False

    log_job = logjob.LogJob(vmx_device_handle, log_dir=DEFAULT_LOG_DIR, log_name=LOG_FILE_NAME)

    signal.signal(signal.SIGTERM, log_job.stop_log)
    signal.signal(signal.SIGINT, log_job.stop_log)

    commands = cmdparser.CmdParser.parse_cmd_sp()

    pprint(commands)

    if commands is not None:
        policies = commands.policies
        if policies is not None:
            p_processor = policyprocessor.PolicyProcessor(vmx_device_handle, policies)
            p_processor.parse_policy()

        if commands.log:
            log_on = log_job.start_log()

        if commands.script:
            script_processor = vlscript.VlScript(logdir=DEFAULT_LOG_DIR, log_suffix=LOG_FILE_SUFFIX)
            script_processor.script()

    if log_on:
        try:
            log_job.start()

            while True:
                time.sleep(0.5)

        except logjob.LoggerExit:
            log_job.shutdown_flag.set()
            log_job.join()

    print('Exiting vbh logger.')

if __name__ == '__main__':
    singleton_app()
    main()