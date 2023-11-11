#!/bin/bash
# EY audit script
#
# Copyright: EY / Ernst & Young GmbH
#
# Please read instructions before executing
#
STARTEND="=============================================================="
SEPARATOR=" =======> "
CURRENTDIR=`pwd`
BASEDIRNAME="ey_audit_os_`hostname`_`date +%Y%m%d%m%s`"
TMP_ROOT="/tmp"
TMP_DIR="${TMP_ROOT}/ey_audit/"
BASEDIR="${TMP_DIR}${BASEDIRNAME}"
LOGFILE="${BASEDIR}/log.out"
MINFREESPACE_MB=500
FINDALL="nice -19 find /   "
TIMEOUT=1200 #sec

#Check user running the script
if [[ $UID -ne 0 ]]; then
    echo "$0 must be run as root"
    exit 1
fi

#Check free disk space
re='^[0-9]+$'
freespace=$(df $TMP_ROOT | grep % | grep -v Use%|awk '{print $4}')
if ! [[ $freespace =~ $re ]]; then
	freespace=$(df $TMP_ROOT | grep % | grep -v Use%|awk '{print $3}')
	if ! [[ $freespace =~ $re ]]; then
		freespace=$(df . | grep % | grep -v %used|awk '{print $2}')
	fi
fi

freespace=$(($freespace / 1024))
if [ $freespace -lt $MINFREESPACE_MB ] ;then
	echo "There is only $freespace MB disk space left on $TMP_ROOT."
	echo "The size of the script outputs may exceed the free space."
	echo "Please ensure that there is at least $MINFREESPACE_MB MB free space left and run the script again."
	echo "As an alternative change the destination directory by modifying the variable TMP_ROOT."
	exit 1
fi

#create output directory
mkdir -p $BASEDIR
chmod 700 $BASEDIR

#write system details into logfile
echo "Hostname: `hostname`" >> $LOGFILE
echo "System: `uname -a`" >> $LOGFILE
echo "Execute as: `whoami`" >> $LOGFILE

#Save a copy of this script in output directory
cp $0 ${BASEDIR}/script.out >> $LOGFILE 2>> $LOGFILE

#Execute the various audit commands while logging the respective outputs and errors
do_test()
{
	echo "Processing $COMMAND"
	echo $STARTEND >> $LOGFILE
	echo "Command : $COMMAND" >> $LOGFILE
	echo "Description : $DESCRIPTION" >> $LOGFILE
	echo "Started: `date`" >> $LOGFILE
	./hba_timeout.sh -t $TIMEOUT -i 30 -d 10 -l $LOGFILE $COMMAND >> $OUTFILE 2>> $LOGFILE
	echo "ExitCode: $?" >> $LOGFILE
	echo "Output: `du -h $OUTFILE`" >> $LOGFILE
	echo "Finished: `date`" >> $LOGFILE
	echo $STARTEND >> $LOGFILE
	echo "Finished $COMMAND"
	echo $STARTEND
}

#Create helper script used to execute commands with a timeout to terminate audit commands in case necessary
echo "
#!/bin/bash
#

scriptName=\"\${0##*/}\"

declare -i DEFAULT_TIMEOUT=9
declare -i DEFAULT_INTERVAL=1
declare -i DEFAULT_DELAY=1
DEFAULT_LOG=${BASEDIR}/hba_timeout.log

# Timeout.
declare -i timeout=DEFAULT_TIMEOUT
# Interval between checks if the process is still alive.
declare -i interval=DEFAULT_INTERVAL
# Delay between posting the SIGTERM signal and destroying the process by SIGKILL.
declare -i delay=DEFAULT_DELAY
# Set log for out timed processes
log=\$DEFAULT_LOG

function printUsage() {
    cat <<EOF

Synopsis
    \$scriptName [-t timeout] [-i interval] [-d delay] command
    Execute a command with a time-out.
    Upon time-out expiration SIGTERM (15) is sent to the process. If SIGTERM
    signal is blocked, then the subsequent SIGKILL (9) terminates it.

    -t timeout
        Number of seconds to wait for command completion.
        Default value: \$DEFAULT_TIMEOUT seconds.

    -i interval
        Interval between checks if the process is still alive.
        Positive integer, default value: \$DEFAULT_INTERVAL seconds.

    -d delay
        Delay between posting the SIGTERM signal and destroying the
        process by SIGKILL. Default value: \$DEFAULT_DELAY seconds.

	-l log
		Write log to file. Default value: \$DEFAULT_LOG

As of today, Bash does not support floating point arithmetic (sleep does),
therefore all delay/time values must be integers.
EOF
}

# Options.
while getopts \":t:i:d:l:\" option; do
    case \"\$option\" in
        t) timeout=\$OPTARG ;;
        i) interval=\$OPTARG ;;
        d) delay=\$OPTARG ;;
		l) log=\$OPTARG ;;
        *) printUsage; exit 1 ;;
    esac
done
shift \$((OPTIND - 1))

# \$# should be at least 1 (the command to execute), however it may be strictly
# greater than 1 if the command itself has options.
if ((\$# == 0 || interval <= 0)); then
    printUsage
    exit 1
fi

# kill -0 pid   Exit code indicates if a signal may be sent to \$pid process.
(
    ((t = timeout))

    while ((t > 0)); do
        sleep \$interval
        kill -0 \$\$ || exit 0
        ((t -= interval))
    done

    # Be nice, post SIGTERM first.
    # The 'exit 0' below will be executed if any preceeding command fails.
    kill -s SIGTERM \$\$ && kill -0 \$\$ || exit 0
	echo "Process was killed after timeout." >> \$log
#    sleep \$delay
#    kill -s SIGKILL \$\$
) 2> /dev/null &

exec \"\$@\"
" > ./hba_timeout.sh
chmod u+x hba_timeout.sh
#Script info:
#OStype:redhat
#GenDate:20200710-141823

#Create helper script used for various audit commands

echo "#!/bin/bash
#Helper to perform the following task: Copy /etc/shadow file without the hashes
if [ \"\$1\" == \"0\" ]; then
while read -r line;
do
	echo \"\$line\" | awk -F \":\" ' !/\\\$/ {print \$1 \":\" substr(\$2,1,5) \"###:\" \$3 \":\" \$4 \":\" \$5 \":\" \$6 \":\" \$7 \":\" \$8} ';
	echo \"\$line\" | awk -F \":\" '  \$2 ~ /\\\$/ {print \$1 \":\" substr(\$2,1,17) \"###:\" \$3 \":\" \$4 \":\" \$5 \":\" \$6 \":\" \$7 \":\" \$8} ';
done < /etc/shadow
fi

#Helper to perform the following task: List privileges for crontab scripts
if [ \"\$1\" == \"1\" ]; then
while read line; do ls -al \"\$line\";done <<< \$(grep -v \"#\" -r /var/spool/cron/ | awk '{print \$6}' | grep '^/')
fi

#Helper to perform the following task: Get current status (locked/open) for each user
if [ \"\$1\" == \"2\" ]; then
while read line;
do
	user=\$(echo \$line | awk -F \":\" ' { print \$1 } ')
	if [ \$(passwd -S \$user | cut -d \" \" -f2) == \"L\" ]; then echo \"\$user is locked\"; else echo \"\$user is NOT locked\"; fi;
done < /etc/passwd
fi

#Helper to perform the following task: List permissions for new created files (umask)
if [ \"\$1\" == \"3\" ]; then
umask; cat /etc/login.defs | grep UMASK | grep -v '#' ; cat /etc/profile /home/*/.bashrc | grep umask
fi

#Helper to perform the following task: Copy nispasswd without hashes
if [ \"\$1\" == \"4\" ]; then
while read line;
do
	echo \"\$line\" | nawk -F\":\" ' {print \$1 \":\" substr(\$2,1,6) \"###:\" \$3 \":\" \$4 \":\" \$5 \":\" \$6} ';
done <<< \$(ypcat passwd)
fi

#Helper to perform the following task: List installed java version
if [ \"\$1\" == \"5\" ]; then
java -version 2>&1
fi

#Helper to perform the following task: Lists permissions for all files ignoring bash_completion, processes and devices
if [ \"\$1\" == \"6\" ]; then
nice -19 find / -mount -not -path \"/etc/bash_completion.d/*\" -not -path \"/proc/*\" -not -path \"/sys/devices/*\" -print0 | xargs -0 ls -ilLpd ;
fi

#Helper to perform the following task: Find and copy the umask - default permissions that are assigned to new files and folder
if [ \"\$1\" == \"7\" ]; then
find /etc /home/ /root \\( -name \"profile\" -or  -name \"login.defs\" -or -name \".bashrc\" \\) -type f -exec echo \"$SEPARATOR\" {} \\; -exec ls -ailL {} \\; -exec grep 'umask\\|UMASK' {} \\;
fi

" > ./hba_helper.sh
chmod u+x ./hba_helper.sh


#Execute audit commands using the previously defined function

DESCRIPTION="Copy /etc/shadow file without the hashes"
COMMAND='./hba_helper.sh 0'
OUTFILE="$BASEDIR/shadow.out"
do_test

DESCRIPTION="Copy file containing the list of local users and corresponding configurations"
COMMAND="cat /etc/passwd"
OUTFILE="$BASEDIR/passwd.out"
do_test

DESCRIPTION="Copy files containing the Release-Name and the Version-Information of distribution"
COMMAND="cat /etc/*version /etc/*release"
OUTFILE="$BASEDIR/version.out"
do_test

DESCRIPTION="Get name, version and other details about the current machine and the operating system"
COMMAND="uname -a"
OUTFILE="$BASEDIR/uname.out"
do_test

DESCRIPTION="Get the user executing the script"
COMMAND="whoami"
OUTFILE="$BASEDIR/whoami.out"
do_test

DESCRIPTION="List privileges for crontab scripts"
COMMAND='./hba_helper.sh 1'
OUTFILE="$BASEDIR/cron_spool_perm.out"
do_test

DESCRIPTION="List the current sessions on the system"
COMMAND="who"
OUTFILE="$BASEDIR/who.out"
do_test

DESCRIPTION="List kernel modules currently loaded"
COMMAND="lsmod"
OUTFILE="$BASEDIR/lsmod.out"
do_test

DESCRIPTION="Copy file containing the message printed to the user after login"
COMMAND="cat /etc/issue"
OUTFILE="$BASEDIR/issue.out"
do_test

DESCRIPTION="Copy file containing the message printed to the user after login"
COMMAND="cat /etc/issue.net"
OUTFILE="$BASEDIR/issue.net.out"
do_test

DESCRIPTION="Get current status (locked/open) for each user"
COMMAND='./hba_helper.sh 2'
OUTFILE="$BASEDIR/user_status.out"
do_test

DESCRIPTION="Copy file containing local user groups"
COMMAND="cat /etc/group"
OUTFILE="$BASEDIR/group.out"
do_test

DESCRIPTION="List the groups that the current user is member of"
COMMAND="groups"
OUTFILE="$BASEDIR/groups.out"
do_test

DESCRIPTION="List file permissions for /etc/shadow where password-hashes are stored"
COMMAND="ls -alLi /etc/shadow"
OUTFILE="$BASEDIR/shadow.perm.out"
do_test

DESCRIPTION="Check integrity of user authentication information"
COMMAND="pwck -r"
OUTFILE="$BASEDIR/pwck.r.out"
do_test

DESCRIPTION="Copy file containing the list of privileges assigned to sudoers"
COMMAND="cat /etc/sudoers"
OUTFILE="$BASEDIR/sudoers.out"
do_test

DESCRIPTION="Copy file containing default settings for user creation, such as expiry date"
COMMAND="cat /etc/default/useradd"
OUTFILE="$BASEDIR/useradd_defaults.out"
do_test

DESCRIPTION="Copy file containing default settings for login"
COMMAND="cat /etc/login.defs"
OUTFILE="$BASEDIR/login.defs.out"
do_test

DESCRIPTION="Copy file containing the list of commands run at user login"
COMMAND="cat /etc/profile"
OUTFILE="$BASEDIR/profile.out"
do_test

DESCRIPTION="List permissions for new created files (umask)"
COMMAND='./hba_helper.sh 3'
OUTFILE="$BASEDIR/umask.out"
do_test

DESCRIPTION="List the history of account logins"
COMMAND="last"
OUTFILE="$BASEDIR/last.out"
do_test

DESCRIPTION="Copy file containing the list of shells that are allowed to be used"
COMMAND="cat /etc/shells"
OUTFILE="$BASEDIR/shells.out"
do_test

DESCRIPTION="Copy file containing the list of users not allowed to use ftp"
COMMAND="cat /etc/ftpusers"
OUTFILE="$BASEDIR/ftpusers.out"
do_test

DESCRIPTION="List file permissions for logs of user logins/logouts/system events"
COMMAND="ls -ailL /var/run/utmp /var/log/wtmp"
OUTFILE="$BASEDIR/utmp.wtmp.perm.out"
do_test

DESCRIPTION="Copy file containing the configuration of syslog - logging service"
COMMAND="cat /etc/syslog.conf"
OUTFILE="$BASEDIR/syslog.conf.out"
do_test

DESCRIPTION="Copy files containing configuration of syslog-ng - logging service"
COMMAND="cat /etc/syslog-ng.conf /etc/syslog-ng/syslog-ng.conf /opt/etc/syslog-ng.conf /opt/syslog-ng/etc/syslog-ng.conf"
OUTFILE="$BASEDIR/syslog-ng.conf.out"
do_test

DESCRIPTION="Copy file containing the configuration of rsyslog (Logging-Service)"
COMMAND="cat /etc/rsyslog.conf"
OUTFILE="$BASEDIR/rsyslog.conf.out"
do_test

DESCRIPTION="Find and copy the rsyslog.d configuration"
COMMAND="find /etc/rsyslog.d/   -type f -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/rsyslog.d.out"
do_test

DESCRIPTION="Copy file containing the list of services and ports that they run on"
COMMAND="cat /etc/services"
OUTFILE="$BASEDIR/services.out"
do_test

DESCRIPTION="List current listening ports"
COMMAND="netstat -lneep"
OUTFILE="$BASEDIR/netstat.lneep.out"
do_test

DESCRIPTION="List current connections with additional information"
COMMAND="netstat -aneep"
OUTFILE="$BASEDIR/netstat.aneep.out"
do_test

DESCRIPTION="Extract routing information"
COMMAND="netstat -rn"
OUTFILE="$BASEDIR/netstat.rn.out"
do_test

DESCRIPTION="List all the registered RPC services (portmapper)"
COMMAND="rpcinfo -p"
OUTFILE="$BASEDIR/rpcinfo.p.out"
do_test

DESCRIPTION="List all network interfaces and current configuration"
COMMAND="ifconfig -a"
OUTFILE="$BASEDIR/ifconfig.a.out"
do_test

DESCRIPTION="Copy file containing the list of used DNS servers "
COMMAND="cat /etc/resolv.conf"
OUTFILE="$BASEDIR/resolv.conf.out"
do_test

DESCRIPTION="Copy file containing local mapping from hostname to IPs"
COMMAND="cat /etc/hosts"
OUTFILE="$BASEDIR/hosts.out"
do_test

DESCRIPTION="Copy file containing the list of trusted hosts for a remote system"
COMMAND="cat /etc/hosts.equiv"
OUTFILE="$BASEDIR/hosts.equiv.out"
do_test

DESCRIPTION="Copy file containing the list of trusted hosts that are allowed to use local print services"
COMMAND="cat /etc/hosts.lpd"
OUTFILE="$BASEDIR/hosts.lpd.out"
do_test

DESCRIPTION="Copy file containing the list of IPs and hosts that are allowed to access certain network services"
COMMAND="cat /etc/hosts.allow"
OUTFILE="$BASEDIR/hosts.allow.out"
do_test

DESCRIPTION="Copy file containing the list of IPs and hosts that are NOT allowed to access certain network services"
COMMAND="cat /etc/hosts.deny"
OUTFILE="$BASEDIR/hosts.deny.out"
do_test

DESCRIPTION="Copy file containing the configuration for Network Time Protocol (ntp)"
COMMAND="cat /etc/ntp.conf"
OUTFILE="$BASEDIR/ntp.conf.out"
do_test

DESCRIPTION="Lists mounted file systems"
COMMAND="mount"
OUTFILE="$BASEDIR/mount.out"
do_test

DESCRIPTION="Copy file containing the list of file systems mounted at startup"
COMMAND="cat /etc/fstab"
OUTFILE="$BASEDIR/fstab.out"
do_test

DESCRIPTION="Copy file containing the list of folders exported via NFS"
COMMAND="cat /etc/exports"
OUTFILE="$BASEDIR/exports.out"
do_test

DESCRIPTION="List folders exported via nfs"
COMMAND="showmount -e"
OUTFILE="$BASEDIR/showmount.e.out"
do_test

DESCRIPTION="Copy file containing network groups, containing sets of (host, user, domain) tuples, used for permission checking for remote mounts, remote logins and remote shells"
COMMAND="cat /etc/netgroup"
OUTFILE="$BASEDIR/netgroup.out"
do_test

DESCRIPTION="Copy file containing name service configuration for lookup order for NSS (Name  Service  Switch)"
COMMAND="cat /etc/nsswitch.conf"
OUTFILE="$BASEDIR/nsswitch.conf.out"
do_test

DESCRIPTION="Get the name of the NIS server that supplies the NIS services"
COMMAND="ypwhich"
OUTFILE="$BASEDIR/nis.out"
do_test

DESCRIPTION="Copy nispasswd without hashes"
COMMAND='./hba_helper.sh 4'
OUTFILE="$BASEDIR/nispasswd.out"
do_test

DESCRIPTION="List the host/ip mapping distributed via NIS"
COMMAND="ypcat hosts"
OUTFILE="$BASEDIR/nishosts.out"
do_test

DESCRIPTION="List the groups distributed via NIS"
COMMAND="ypcat group"
OUTFILE="$BASEDIR/nisgroup.out"
do_test

DESCRIPTION="Lists the current environment"
COMMAND="bash -c set"
OUTFILE="$BASEDIR/set.out"
do_test

DESCRIPTION="Copy file containing a list of terminals which may transmit certain authentication tokens"
COMMAND="cat /etc/securetty"
OUTFILE="$BASEDIR/securetty.out"
do_test

DESCRIPTION="Copy file containing the list of users that are allowed to access the crontab"
COMMAND="cat /etc/cron.d/cron.allow"
OUTFILE="$BASEDIR/cron.allow.out"
do_test

DESCRIPTION="Copy file containing the list of users that are NOT allowed to access the crontab"
COMMAND="cat /etc/cron.d/cron.deny"
OUTFILE="$BASEDIR/cron.deny.out"
do_test

DESCRIPTION="Get whether or not access control is currently enabled and extract a list of those allowed to connect"
COMMAND="xhost"
OUTFILE="$BASEDIR/xhost.out"
do_test

DESCRIPTION="Copy file containing the list of network services that are started by inetd on demand"
COMMAND="cat /etc/inetd.conf"
OUTFILE="$BASEDIR/inetd.conf.out"
do_test

DESCRIPTION="Copy file containing the list of network services that are started by xinetd on demand"
COMMAND="cat /etc/xinetd.conf"
OUTFILE="$BASEDIR/xinetd.conf.out"
do_test

DESCRIPTION="Copy file containing the system initialization processes/tasks"
COMMAND="cat /etc/inittab"
OUTFILE="$BASEDIR/inittab.out"
do_test

DESCRIPTION="Get current status of the local firewall"
COMMAND="/etc/init.d/iptables status"
OUTFILE="$BASEDIR/iptables.status.out"
do_test

DESCRIPTION="List local firewall rules"
COMMAND="iptables -L"
OUTFILE="$BASEDIR/iptables.rules.out"
do_test

DESCRIPTION="List firewall NAT rules"
COMMAND="iptables -L -t nat"
OUTFILE="$BASEDIR/iptables.rules.nat.out"
do_test

DESCRIPTION="List firewall rules from the mangle table"
COMMAND="iptables -L -t mangle"
OUTFILE="$BASEDIR/iptables.rules.mangle.out"
do_test

DESCRIPTION="Find and list files without owner or group"
COMMAND="nice -19 find / -mount -nouser -or -nogroup"
OUTFILE="$BASEDIR/orpheans.out"
do_test

DESCRIPTION="Find and copy the network configuration"
COMMAND="find /etc/network*   -type f -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/ifcfg.out"
do_test

DESCRIPTION="Find and copy the configuration information for login and user authentication"
COMMAND="find /etc /usr/local/etc ( -name login.cfg -o -name login2.cfg )   -exec echo  =======>  {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/login.cfg.out"
do_test

DESCRIPTION="Find and copy the environment settings for all users"
COMMAND="find /etc /usr/local/etc ( -name bash.bashrc -o -name zshrc )   -exec echo  =======>  {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/bash_zsh.out"
do_test

DESCRIPTION="Find and list executable that can be run by everbody and run under the privileges of the file owner which have not been accessed for 100 days"
COMMAND="nice -19 find / -mount -type f  ( -perm +2000 -or -perm +6000 )   -atime +100 -perm +g=x,o=x"
OUTFILE="$BASEDIR/suid-sgid-non-used.out"
do_test

DESCRIPTION="List file permissions for security configuration files"
COMMAND="ls -aliL /etc/security/"
OUTFILE="$BASEDIR/security.ls.out"
do_test

DESCRIPTION="Find and copy kernel IPv4 parameters"
COMMAND="find /proc/sys/net/ipv4   -type f -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/ipv4.param.out"
do_test

DESCRIPTION="Find and copy kernel IPv6 parameters"
COMMAND="find /proc/sys/net/ipv6   -type f -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/ipv6.param.out"
do_test

DESCRIPTION="Find and copy the configuration for network services that are started by xinetd on demand"
COMMAND="find /etc/xinetd.d   -type f -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/xinetd.d.files.out"
do_test

DESCRIPTION="Find and copy the scripts executed at startup and shutdown"
COMMAND="find /etc/rc*   -type f -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/rc.out"
do_test

DESCRIPTION="List file permissions for startup and shudown scripts"
COMMAND="ls -ai -lR /etc/rc*"
OUTFILE="$BASEDIR/rc_ls.out"
do_test

DESCRIPTION="Find and copy configured cronjobs "
COMMAND="find /var/spool/cron /etc/cron* -type f -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/cron_spool.out"
do_test

DESCRIPTION="Find and list file permissions of cronjobs"
COMMAND="find /var/spool/cron /etc/cron* -type f -exec ls -ailL {} ;"
OUTFILE="$BASEDIR/cron_perm.out"
do_test

DESCRIPTION="Find and copy the scripts executed at startup and shutdown"
COMMAND="find /etc/init*  -type f -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/init.out"
do_test

DESCRIPTION="Find and copy the pam configuration (authentification)"
COMMAND="find /etc/pam.d   -type f -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/pam.d.out"
do_test

DESCRIPTION="Copy file containing configuration of the Privilege Access Management (pam), which specifies authentification services - legacy"
COMMAND="cat /etc/pam.conf"
OUTFILE="$BASEDIR/pam.conf.out"
do_test

DESCRIPTION="Find and copy the ssh configuration"
COMMAND="find /etc /usr/local/etc   ( -name sshd_config -o -name ssh2d_config ) -exec echo  =======>  {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/ssh.out"
do_test

DESCRIPTION="Find and copy the permissions for sudoers"
COMMAND="find /etc -name sudoers   -exec echo  =======>  {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/sudo.out"
do_test

DESCRIPTION="Find and list permissions for log files"
COMMAND="find /var/log   -type f -exec ls -ailL {} ;"
OUTFILE="$BASEDIR/logs.perm.out"
do_test

DESCRIPTION="Find and list the device permissions"
COMMAND="find /dev   -exec ls -ailL {} ;"
OUTFILE="$BASEDIR/dev.perm.out"
do_test

DESCRIPTION="Find and copy the default parameters for users"
COMMAND="find /etc   ( -name profile -o -name cshrc -o -name csh.login -o -name .login -o -name login ) -type f -exec echo  =======>  {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/generic.profile.out"
do_test

DESCRIPTION="Find and copy the aliases for accounts. Aliases are used to have multiple names for a single account"
COMMAND="find /etc   ( -name sendmail.cf -o -name aliases ) -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/sendmail.out"
do_test

DESCRIPTION="Find and list files that have SUID-Flag set (executable with privileges of the owner)"
COMMAND="nice -19 find / -mount -type f -perm -004000 -exec ls -ailL {} ; -exec file {} ;"
OUTFILE="$BASEDIR/suid.out"
do_test

DESCRIPTION="Find and list executable files that have SUID-Flag set (executable with privileges of the owner)"
COMMAND="nice -19 find / -mount -type f -perm -004001 -exec ls -ailL {} ;"
OUTFILE="$BASEDIR/suid_ls.out"
do_test

DESCRIPTION="Find and list files that have SGID-Flag set (executable with privileges of the group)"
COMMAND="nice -19 find / -mount -type f -perm -002000 -exec ls -ailL {} ; -exec file {} ;"
OUTFILE="$BASEDIR/sgid.out"
do_test

DESCRIPTION="Find and list directories that are writeable by everyone"
COMMAND="nice -19 find / -mount -type d -perm -002 -exec ls -adilL {} ;"
OUTFILE="$BASEDIR/wwd.out"
do_test

DESCRIPTION="Find and list files writeable by everyone"
COMMAND="nice -19 find / -mount -type f -perm -002 -not -path \"/proc/*\" -exec ls -ailL {} ;"
OUTFILE="$BASEDIR/wwf.out"
do_test

DESCRIPTION="Find and list directories that are writeable by group"
COMMAND="nice -19 find / -mount -type d -perm -0020 -not -path \"/proc/*\" -exec ls -adliL {} ;"
OUTFILE="$BASEDIR/gwd.out"
do_test

DESCRIPTION="Find and list files writeable by group"
COMMAND="nice -19 find / -mount -type f -perm -0020 -not -path \"/proc/*\" -exec ls -ailL {} ;"
OUTFILE="$BASEDIR/gwf.out"
do_test

DESCRIPTION="Find and copy list of users that are allowed to log in remotely from the specified host without having to supply a password"
COMMAND="nice -19 find / -mount ( -name .rhosts -o -name .shosts ) -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/rhosts.out"
do_test

DESCRIPTION="Find and copy login and initialization information used by the auto-login process"
COMMAND="nice -19 find / -mount -name .netrc -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/netrc.out"
do_test

DESCRIPTION="Find and copy .forward file for users (mail forwards)"
COMMAND="nice -19 find / -mount -name .forward -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/forward.out"
do_test

DESCRIPTION="Find and list devices"
COMMAND="nice -19 find / -mount -name dev -prune -o ( -type b -o -type c ) -exec ls -ailL {} ;"
OUTFILE="$BASEDIR/dev.outside.out"
do_test

DESCRIPTION="Find and copy parameters set for user profiles"
COMMAND="nice -19 find /  -mount ( -name .*profile* -o -name .*shrc* -o -name .*login* -o -name .*logout* -o -name .bashrc ) -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/perso.profile.out"
do_test

DESCRIPTION="Find and list the file permissions for files in the webroot"
COMMAND="nice -19 find /var/www/ -mount -exec ls -ilLpd {} ;"
OUTFILE="$BASEDIR/www_ls.out"
do_test

DESCRIPTION="Copy file containing the MySQL-Configuration"
COMMAND="cat /etc/my.cnf"
OUTFILE="$BASEDIR/my.conf.out"
do_test

DESCRIPTION="List file permissions for php-Files"
COMMAND="ls -alRiL /etc/php*"
OUTFILE="$BASEDIR/php_ls.out"
do_test

DESCRIPTION="List file permissions for config files for mysql"
COMMAND="ls -alRiL /etc/mysql*"
OUTFILE="$BASEDIR/mysql_ls.out"
do_test

DESCRIPTION="List all installed packages"
COMMAND="rpm -qai"
OUTFILE="$BASEDIR/packages.rpm.out"
do_test

DESCRIPTION="List current connections"
COMMAND="netstat -anp"
OUTFILE="$BASEDIR/netstat.a.out"
do_test

DESCRIPTION="Find and copy the interface configuration that control the software interfaces for individual network devices"
COMMAND="find /etc/sysconfig/network-scripts   -name "ifcfg*" -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/ifcfg2.out"
do_test

DESCRIPTION="Find and copy the configuration files for apache"
COMMAND="find /etc/httpd/ -type f ! -iname magic -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/apache.out"
do_test

DESCRIPTION="List file permissions for apache config files"
COMMAND="ls -aliLR /etc/httpd"
OUTFILE="$BASEDIR/apache_conf_ls.out"
do_test

DESCRIPTION="Copy file containing the list of file systems mounted at startup"
COMMAND="cat /etc/filesystems"
OUTFILE="$BASEDIR/filesystems.out"
do_test

DESCRIPTION="List the netgroups"
COMMAND="ypcat netgroup"
OUTFILE="$BASEDIR/nisnetgroup.out"
do_test

DESCRIPTION="List current connections"
COMMAND="netstat -an"
OUTFILE="$BASEDIR/netstat.an.out"
do_test

DESCRIPTION="List all running processes including all details"
COMMAND="ps -alef"
OUTFILE="$BASEDIR/ps.alef.out"
do_test

DESCRIPTION="List files executed at startup and shutdown and their privileges"
COMMAND="ls -al /etc/init.d/"
OUTFILE="$BASEDIR/ls.initd.out"
do_test

DESCRIPTION="Find and list executable files with SGID-Flag set (executable with privileges of the group)"
COMMAND="nice -19 find / -mount -type f -perm -002001 -exec ls -ailL {} ;"
OUTFILE="$BASEDIR/sgid_ls.out"
do_test

DESCRIPTION="Copy file containing the ssh(Secure Shell)-Configuration"
COMMAND="cat /etc/ssh/sshd_config"
OUTFILE="$BASEDIR/ssh2.out"
do_test

DESCRIPTION="Copy file containing the list of network services that are started by inetd on demand"
COMMAND="cat /etc/inetd.conf"
OUTFILE="$BASEDIR/inetd.conf.out"
do_test

DESCRIPTION="List shared folders"
COMMAND="share"
OUTFILE="$BASEDIR/share.out"
do_test

DESCRIPTION="Find and copy security configuration"
COMMAND="find /etc/security -type f -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/etc_security.out"
do_test

DESCRIPTION="List all software installed from yum"
COMMAND="yum list installed"
OUTFILE="$BASEDIR/yum.list.installed.out"
do_test

DESCRIPTION="Get packages not installed from standard repository"
COMMAND="yum list extras"
OUTFILE="$BASEDIR/yum.list.extras.out"
do_test

DESCRIPTION="List global and group level password policies from IPA"
COMMAND="ipa pwpolicy-show "
OUTFILE="$BASEDIR/ipa.pwpolicy-show.out"
do_test

DESCRIPTION="Copy file containing the list of password quality requirements"
COMMAND="cat /etc/security/pwquality.conf"
OUTFILE="$BASEDIR/pwquality.conf.out"
do_test

DESCRIPTION="Copy file containing the general configuration for apache web server"
COMMAND="cat /etc/httpd/conf/httpd.conf"
OUTFILE="$BASEDIR/apache.httpd.out"
do_test

DESCRIPTION="Copy file containing the SSL config for apache web server"
COMMAND="cat /etc/httpd/conf.d/ssl.conf"
OUTFILE="$BASEDIR/apache.ssl.out"
do_test

DESCRIPTION="Copy file containing the php-Configuration"
COMMAND="cat /etc/php.ini"
OUTFILE="$BASEDIR/php.ini.out"
do_test

DESCRIPTION="Get php version"
COMMAND="php -v"
OUTFILE="$BASEDIR/php.v.out"
do_test

DESCRIPTION="List installed java version"
COMMAND='./hba_helper.sh 5'
OUTFILE="$BASEDIR/java.out"
do_test

DESCRIPTION="List all running processes with basic details"
COMMAND="ps awux"
OUTFILE="$BASEDIR/ps.awux.out"
do_test

DESCRIPTION="List services and their status"
COMMAND="service --status-all"
OUTFILE="$BASEDIR/service.status.all.out"
do_test

DESCRIPTION="List file permissions for /etc/shadow where password-hashes are stored"
COMMAND="ls -alLiZ /etc/shadow"
OUTFILE="$BASEDIR/shadow.Z.perm.out"
do_test

DESCRIPTION="Copy file containing the log file for yum updates (package management)"
COMMAND="cat /var/log/yum.log"
OUTFILE="$BASEDIR/yum.log.out"
do_test

DESCRIPTION="Copy file containing the policy and main configuration of selinux (Security Enhanced Linux)"
COMMAND="cat /etc/selinux/config"
OUTFILE="$BASEDIR/selinux.conf.out"
do_test

DESCRIPTION="Find and copy the configuration for vsftpd"
COMMAND="find /etc/  -name "vsftpd.conf"  -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/ftp_vsftpd.out"
do_test

DESCRIPTION="Copy file containing the list of users allowed or denied login via vsftpd"
COMMAND="cat /etc/vsftpd/user_list"
OUTFILE="$BASEDIR/vsftpd.user_list.out"
do_test

DESCRIPTION="List all the registered RPC services"
COMMAND="rpcinfo"
OUTFILE="$BASEDIR/rpcinfo.out"
do_test

DESCRIPTION="Copy file containing the configuration of proftp (File Transfer Protocol)"
COMMAND="cat /etc/proftpd.conf"
OUTFILE="$BASEDIR/ftp.proftpd.out"
do_test

DESCRIPTION="List all running processes including all details"
COMMAND="ps -Alf"
OUTFILE="$BASEDIR/ps.Alf.out"
do_test

DESCRIPTION="Get the ip of the loghost"
COMMAND="host loghost"
OUTFILE="$BASEDIR/loghost.out"
do_test

DESCRIPTION="Find and copy list of authorized public keys for SSH connection"
COMMAND="nice -19 find / -mount ( -name authorized_keys  ) -exec echo  =======>  {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/ssh_authorized_keys.out"
do_test

DESCRIPTION="List file permissions for the passwd-File"
COMMAND="ls -alLi /etc/passwd"
OUTFILE="$BASEDIR/ls.passwd.out"
do_test

DESCRIPTION="Lists permissions for all files ignoring bash_completion, processes and devices"
COMMAND='./hba_helper.sh 6'
OUTFILE="$BASEDIR/ls.all.root.out"
do_test

DESCRIPTION="Get current status of the local firewall"
COMMAND="service firewalld status"
OUTFILE="$BASEDIR/iptables.service.status.out"
do_test

DESCRIPTION="Get the openssl version"
COMMAND="openssl version"
OUTFILE="$BASEDIR/openssl.version.out"
do_test

DESCRIPTION="List the ciphers supported by openssl"
COMMAND="openssl ciphers -v -s HIGH"
OUTFILE="$BASEDIR/openssl.ciphers.out"
do_test

DESCRIPTION="Find and copy security configuration"
COMMAND="find /etc/security/   -type f -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/etc.security.out"
do_test

DESCRIPTION="Find and copy additional logging configurations"
COMMAND="find /var/run/rsyslog/   -type f -exec echo $SEPARATOR {} ; -exec ls -ailL {} ; -exec cat {} ;"
OUTFILE="$BASEDIR/rsyslog.additional.out"
do_test

DESCRIPTION="Find and copy the umask - default permissions that are assigned to new files and folder"
COMMAND='./hba_helper.sh 7'
OUTFILE="$BASEDIR/umask.a.out"
do_test

DESCRIPTION="Lists the current vmware tools version"
COMMAND="/usr/bin/vmware-toolbox-cmd -v"
OUTFILE="$BASEDIR/vmware.tools.out"
do_test

DESCRIPTION="Copy file containing the FTP-Server configuration, containing e.g. FTP-Access Rights"
COMMAND="cat /etc/ftpaccess"
OUTFILE="$BASEDIR/etc.ftpaccess.out"
do_test

DESCRIPTION="Copy file containing the configuration of the audit daemon"
COMMAND="cat /etc/audit/auditd.conf"
OUTFILE="$BASEDIR/etc.audit.auditd.conf.out"
do_test



#Remove temporary helper files
rm ./hba_timeout.sh
rm ./hba_helper.sh

#Save integrity information
FCOUNT=0
FCHRCOUNT=0
for f in $BASEDIR/* ; do sha256sum $f >> $BASEDIR/files.out 2>> $LOGFILE; FCOUNT=$(($FCOUNT + 1)); FCHRCOUNT=$(($FCHRCOUNT + ${#f})); done
echo $FCOUNT $FCHRCOUNT >>$BASEDIR/files.out

#Check free disk space

usedspace=$(du -s ${BASEDIR} | grep ${BASEDIR} | awk '{print $1}')
freespace=$(df . | grep % | grep -v Use%|awk '{print $4}')
if ! [[ $freespace =~ $re ]]; then
	freespace=$(df . | grep % | grep -v Use%|awk '{print $3}')
	if ! [[ $freespace =~ $re ]]; then
		freespace=$(df . | grep % | grep -v %used|awk '{print $2}')
	fi
fi

if [[ $freespace -lt $usedspace ]] ;then
	echo "There is not enough space left on the current working directory to create the archive."
	echo "Please create the archive manually."
	echo "The files are located at ${BASEDIR}"
	exit 1
fi

#Create results archive
echo "Creating an archive containing the following files:"
tarfile=${BASEDIRNAME}.tar
tar -C ${BASEDIR}/../ -cvf ${CURRENTDIR}/${tarfile} ${BASEDIRNAME}
chmod 400 $tarfile
if [[ -s ${tarfile} ]]; then
	echo ""
	echo "Files have been stored in $tarfile."
	echo ""
	echo "A temporary folder was created during the process. It may contain temporary data of other EY audit script executions."
	echo "Would you like to delete it?"
	echo "Temporary folder: $TMP_DIR"
	read -p "Press y to delete the files : " inputr
	if [[ "$inputr" == "y" ]]; then
		rm -r $TMP_DIR
	fi
fi
