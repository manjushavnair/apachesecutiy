#!/usr/bin/perl
# 
# 

use strict;
use Getopt::Long;

# ~+~+~+~+~+
# http://www.nsa.gov/ia/_files/os/redhat/rhel5-guide-i731.pdf
# ~+~+~+~+~+


$ENV{'PATH'}=$ENV{'PATH'}.":/sbin:/usr/sbin";  # Set internal PATH since we want to use sbin binaries

my $debug = 1;
my $is_normal_user = `id -u`; chomp $is_normal_user;
my %report;
my $output_mode = "screen";

$\ = "\n"; # We want print to act like println


## my @available_audits = qw / partitions all /;
my %available_audits = (
    "partitions" => \&check_partitions,
    "network" => \&check_network,
    "pkgintegrity" => \&check_pkgintegrity,
    "aide" => \&check_aide,
    "fileownership" => \&check_fileownership,
    "exploitprotection" => \&check_exploitprotection,
    "useraccs" => \&check_useraccs,
    "sshd" => \&check_sshd,
    "runningservices" => \&check_runningservices,
    "all" => \&check_all);

my @param_check;
my $help = '';

&validate_params;
&writeHeaders();
&start_audit();
&writeFooters();

sub validate_params {
    my @unknown_params;
    my $temp = GetOptions(
	       'check=s' => \@param_check,
	       'help'    => \$help
	       );

    # Support comma separated values in --check option.
    @param_check = split(/,/, join(',', @param_check)) if (@param_check);
    
    &show_help if (!$temp || $help);
    
    @param_check = "all" if (!@param_check);
    
    @unknown_params = grep {!$available_audits{$_}} @param_check;
    
    if (@unknown_params > 0) {
	print "Invalid argument to option check: @unknown_params\n";
	&show_help;
    }
}

sub start_audit {
    # if @param_check contains "any" then run all tests.
    # else run only the checks asked for.
    if (grep {$_ eq "all"} @param_check) {
	# run all available checks
	&check_all;
    }
    else {
	# run only the checks that were asked for
	my @requested_checks = grep { $available_audits{$_}} @param_check;	
	foreach (@requested_checks) {
	    my $temp = $available_audits{$_};
	    &$temp();
	}
    }
    
}

sub check_all {
    while ( my ($key, $value) = each(%available_audits) ) {
	if ( $key ne "all") {
	    my $temp = $available_audits{$key};
	    &$temp();	    
	}
    }
}

sub show_help {
    my @temp = "";
    @temp = keys %available_audits;
    print <<EOF;
Usage: platform_audit.pl [OPTIONS]
If no command line options are specified, "--check all" is the default. 

[OPTIONS]
    --check [AUDITS]
    --help
    
[AUDITS]
Valid audit values are: @temp
Multiple checks can be run by separating them with comma and without spaces: --check test1,test2

EOF
    exit (1);    
}

sub printOut {
    # Usage: printOut "Severity", "Desc", "Data"
    #if ($_[0] eq "BEGIN")
    
    printscreen(@_) if ($output_mode eq "screen");
}

sub check_partitions {
    my $desc = "Partitioning";
    printOut ("BEGIN","$desc");
    my @conf_fstab = qw(/tmp /var/ /var/log /var/log/audit /home);
    
    open(FSTAB, "</etc/fstab");
    my @mounted;
    
    # TODO: Should I simply use local_partitions instead of going through fstab?
    while (my $line = <FSTAB>) {
	    if (($line !~ /^\#/) && ($line !~ /^$/)) {
		if ($line =~ /(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+.*/) {
		    push(@mounted, $2);
		}
	    }
    }	 
    
    my %mounted = map{$_=>1} @mounted;
    my @unmounted = grep(!defined $mounted{$_},@conf_fstab);
    
    printOut ("INFO", "The following filesystems are not mounted in separate partitions.", "@unmounted");

    if (grep {$_ =~ /^tmpfs.*\/dev\/shm.*$/} `mount`) {
	printOut("INFO", "Found tmpfs mounted on /dev/shm");
    }
    close(FSTAB);
    printOut ("END", "$desc");
}


sub check_network {
    my $desc = "Network configuration.";
    printOut ("BEGIN","$desc");
    my @nwconf = </etc/sysconfig/network-scripts/ifcfg-*>;
    my $dhclient_file;
    foreach (@nwconf){
	next if /.*ifcfg-lo$/;

	/.*ifcfg-(.+)$/;
	if (grep {$_=~ /^BOOTPROTO.*dhcp.*$/} `cat $_`) {
	    printOut "INFO","Network interface $1 uses DHCP.";

	    # RHEL6 first checks /etc/dhcp/dhclient-{DEV}.conf, /etc/dhclient-{DEV}.conf 
	    # and /etc/dhclient.conf. In that order.
	    if (-e "/etc/dhcp/dhclient-$1.conf") {
		$dhclient_file = "/etc/dhcp/dhclient-$1.conf";
	    }
	    elsif (-e "/etc/dhclient-$1.conf") {
		$dhclient_file = "/etc/dhclient-$1.conf";
	    }
	    else {
		$dhclient_file = "/etc/dhclient.conf";
	    }

	    # Open the file and search if all 10 settings are present
	    open(FSDHCP, "<$dhclient_file");
	    
	    my %dhcp_config = (
		"subnet-mask" => 1,
		"broadcast-address" => 1,
		"time-offset" => 1,
		"routers" => 1,
		"domain-name" => 1,
		"domain-name-servers" => 1,
		"host-name" => 1,
		"nis-domain" => 1,
		"nis-servers" => 1,
		"ntp-servers" => 1
		);
	    
	    while (my $line = <FSDHCP>) {
		#dhcp client config file has this format:
		#supersede domain-name "example.com";
		#request subnet-mask;
		if ($line =~ /\s*supersede\s+(\S+)\s+(\S+)\;/) {
		    $dhcp_config{$1} = 0;
		}
	    }
	    close(FSDHCP);
	    
	    my $dhcp_serv_values;
	    my $dhcp_static_values;
	    # Display all items from dhcpclient config that will be received from server
	    while (my($key, $value) = each (%dhcp_config)) {
		$dhcp_serv_values .= " " . $key if ($value == 1);
		$dhcp_static_values .= " " . $key if ($value == 0);
	    }
	    
	    my $msg = "These system settings are received from DHCP server.";
	    printOut ("INFO", $msg,"$dhcp_serv_values") if $dhcp_serv_values;
	    $msg = "These settings are statically configured, and not from DHCP.";
	    printOut ("INFO", $msg, "$dhcp_static_values") if $dhcp_static_values;
	}
	
  
	
	my $net_conf = fgrep('^\s*net.ipv4.ip_forward\s*=\s*0\s*$', '/etc/sysctl.conf');
	printOut "ERROR", "IP Packet forwarding is enabled. This is needed only for router/gateway systems.",
		"Disable it by setting net.ipv4.ip_forward = 0 in /etc/sysctl.conf" if ! $net_conf;

	$net_conf = fgrep('^\s*net.ipv4.conf.all.send_redirects\s*=\s*0\s*$', '/etc/sysctl.conf');
	printOut "ERROR", "The system can send ICMP redirects on *all* interfaces. This is needed only for router/gateway systems.",
		"Disable it by setting net.ipv4.conf.all.send_redirects = 0 in /etc/sysctl.conf" if ! $net_conf;

	$net_conf = fgrep('^\s*net.ipv4.conf.default.send_redirects\s*=\s*0\s*$', '/etc/sysctl.conf');
	printOut "ERROR", "The system can send ICMP redirects on the *default* interface. This is needed only for router/gateway systems.",
		"Disable it by setting net.ipv4.conf.default.send_redirects = 0 in /etc/sysctl.conf" if ! $net_conf;
		
	$net_conf = fgrep('^\s*net.ipv4.conf.all.accept_source_route\s*=\s*0\s*$', '/etc/sysctl.conf');
	my $net_conf2 = fgrep('^\s*net.ipv4.conf.default.accept_source_route\s*=\s*0\s*$', '/etc/sysctl.conf');
	printOut "ERROR", "IP4 accept_source_route is enabled.",
		"Disable it by setting net.ipv4.conf.all.accept_source_route = 0 and " .
		"net.ipv4.conf.default.accept_source_route = 0 in /etc/sysctl.conf" if (! $net_conf) || (! $net_conf2);

	$net_conf = fgrep('^\s*net.ipv4.conf.all.accept_redirects\s*=\s*0\s*$', '/etc/sysctl.conf');
	$net_conf2 = fgrep('^\s*net.ipv4.conf.default.accept_redirects\s*=\s*0\s*$', '/etc/sysctl.conf');
	printOut "ERROR", "IP4 accept_redirects is enabled.",
		"Disable it by setting net.ipv4.conf.all.accept_redirects = 0 and " .
		"net.ipv4.conf.default.accept_redirects = 0 in /etc/sysctl.conf" if ! ($net_conf && $net_conf2);
	
	$net_conf = fgrep('^\s*net.ipv4.conf.all.secure_redirects\s*=\s*0\s*$', '/etc/sysctl.conf');
	$net_conf2 = fgrep('^\s*net.ipv4.conf.default.secure_redirects\s*=\s*0\s*$', '/etc/sysctl.conf');
	printOut "ERROR", "IP4 secure_redirects is enabled.",
		"Disable it by setting net.ipv4.conf.all.secure_redirects = 0 " .
		"net.ipv4.conf.default.secure_redirects = 0 in /etc/sysctl.conf" if ! ($net_conf && $net_conf2);

	$net_conf = fgrep('^\s*net.ipv4.conf.all.log_martians\s*=\s*1\s*$', '/etc/sysctl.conf');
	printOut "ERROR", "IP4 log_martians is disabled.",
		"Disable it by setting net.ipv4.conf.all.log_martians = 1 in /etc/sysctl.conf" if ! $net_conf;
	
	$net_conf = fgrep('^\s*net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*1\s*$', '/etc/sysctl.conf');
	printOut "ERROR", "ICMP echo (ping) broadcasts are not ignored.",
		"Change it by setting net.ipv4.icmp_echo_ignore_broadcasts = 1 in /etc/sysctl.conf" if ! $net_conf;

	$net_conf = fgrep('^\s*net.ipv4.icmp_ignore_bogus_error_messages\s*=\s*1\s*$', '/etc/sysctl.conf');
	printOut "ERROR", "ICMP bogus error messages are not ignored.",
		"Change it by setting net.ipv4.icmp_ignore_bogus_error_messages = 1 in /etc/sysctl.conf" if ! $net_conf;
		
	$net_conf = fgrep('^\s*net.ipv4.tcp_syncookies\s*=\s*1\s*$', '/etc/sysctl.conf');
	printOut "ERROR", "TCP SYN cookies is not enabled.",
		"Change it by setting net.ipv4.tcp_syncookies = 1 in /etc/sysctl.conf" if ! $net_conf;

	$net_conf = fgrep('^\s*net.ipv4.conf.all.rp_filter\s*=\s*1\s*$', '/etc/sysctl.conf');
	$net_conf2 = fgrep('^\s*net.ipv4.conf.default.rp_filter\s*=\s*1\s*$', '/etc/sysctl.conf');
	printOut "ERROR", "IPv4 conf rp_filter is not set.",
		"Change it by setting net.ipv4.conf.all.rp_filter = 1 and " .
		"net.ipv4.conf.default.rp_filter = 1 in /etc/sysctl.conf" if ! ($net_conf && $net_conf2);

	# Check iptables default policies
	if ( ! $is_normal_user ) {
		_validate_fw_policies("iptables");
	} else {
        	printOut "SKIP", "Can't check iptables policies - run this script as a superuser";
	}

	# Check IPv6 configuration
	my @ipv6_ifs = ();
	my %ipv6_sysctls = (
		"net.ipv6.conf.default.router_solicitations"=>0,
		"net.ipv6.conf.default.accept_ra_rtr_pref"=>0,
		"net.ipv6.conf.default.accept_ra_pinfo"=>0,
		"net.ipv6.conf.default.accept_ra_defrtr"=>0,
		"net.ipv6.conf.default.autoconf"=>0,
		"net.ipv6.conf.default.dad_transmits"=>0,
		"net.ipv6.conf.default.max_addresses"=>1
	);
	foreach my $ipv6_if (split "\n", `ip -o -6 addr show`){
		if ($ipv6_if=~/\d+:\s+(\w+\d*)\s+inet6\s+(.*)\/\d+\s+scope\s+(\w+)/){
			push @ipv6_ifs, "$1: $2 ($3)";
		} 
	}
	if (scalar @ipv6_ifs){
        	printOut "INFO", "Detected configured ipv6 interfaces: ".join "; ",@ipv6_ifs;
		# Check IPv6 iptables policies
		if ( ! $is_normal_user ) {
			_validate_fw_policies("ip6tables");
		} else {
        		printOut "SKIP", "Can't check ip6tables policies - run this script as a superuser";
		}
		# Check IPv6 sysctl
		foreach my $sysctl (keys %ipv6_sysctls){
		 	_validate_sysctl($sysctl,$ipv6_sysctls{$sysctl});
		}

	} else {
        	printOut "SKIP", "No ipv6 interfaces detected - skipping checks";
	}
	
    }

    my $_route = `route`;
    printOut ("INFO", "Routing table:", "$_route");
    my $_netstat = `netstat -lep --protocol=inet 2>/dev/null`;
    printOut ("INFO", "Listening INET Ports:", "$_netstat");
    
    printOut ("END", "$desc");
}

sub check_pkgintegrity {
    my $desc = "Package integrity.";
    printOut("BEGIN", "$desc");
    #return if $debug; # This check takes a lot of time. So disable it during development and debugging.
    if (grep {$_ =~ /^\s*gpgcheck\s*=\s*0/} `cat /etc/yum.conf /etc/yum.repos.d/*`) {
	my $msg_desc = "Package signature checking is disabled in atleat one of the yum config files.";
	my $msg_detail = "Files /etc/yum.conf and /etc/yum.repos.d/* were tested. ";
	$msg_detail .= "gpgcheck=0 found in (one or more) yum config files. Turn on signature checking.";
	printOut ("ERROR",$msg_desc, $msg_detail);
    }
    
    # Sometimes rpm -qVa will output a lot of prelink errors. Grep them out using 'Recorded'.
    my $rpm_query = `rpm -qVa  2>/dev/null |awk '\$2!="c" {print \$0}' |grep -v 'Recorded'`;
    my $msg = "Package Integrity Check Results: -------\n$rpm_query\nEnd of Package integrity check output --------";
    printOut ("ERROR","Errors were found during package integrity check.", $msg) if ($rpm_query != "");
    
    printOut ("END", "$desc");
}

sub check_aide {
    my $desc = "AIDE intrusion detection.";
    printOut ("BEGIN", "$desc");
    printOut "INFO","aide is not installed." if (grep {$_ =~ /not/} `rpm -q aide`);
    printOut ("END","$desc");
}



sub check_fileownership {
    my $desc = "File ownerships.";
    printOut ("BEGIN","$desc");
    my @local_filesystems;
    my @tempLocalFileSys = `df -lT |grep -vE '/dev/shm|^Filesystem'`;
    foreach (@tempLocalFileSys) {
        /.*\s+(\S+)$/;
        push(@local_filesystems,$1);
    }     
    
    my @temp = `stat -L -c %U:%G /etc/passwd /etc/shadow /etc/group /etc/gshadow`;
    my $msg = "/etc/passwd, shadow, group or gshadow is not owned by root:root";
    printOut "ERROR", $msg if (grep {$_ !~ /^root:root$/} @temp );
    
    
    @temp = `stat -L -c %a /etc/passwd /etc/group`;
    printOut "ERROR","/etc/passwd or group has insecure permissions. Set it to 644." if (grep {$_ !~ /^644$/} @temp);
    
    # RHEL6 sets perm of (g)shadow to 0. Earlier OS may set it to 400.
    @temp = `stat -L -c %a /etc/shadow /etc/gshadow`;
    printOut "ERROR","/etc/shadow or gshadow has insecure permissions. Set it to 400." if (grep {$_ !~ /^(400|0)$/} @temp);
    
    foreach (@local_filesystems) {
	my $temp =`find $_ -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) -print 2>/dev/null`;
	chomp $temp;
	$msg = "Found world-writable dirs without sticky bit. Use chmod +t <dir> for each of the entries below.";
	printOut("WARN", $msg, "$temp") if ($temp);
    }
    
    foreach (@local_filesystems) {
	my $temp = `find $_ -xdev -type f -perm -0002 -print 2>/dev/null`;
	chomp $temp;
	printOut("WARN", "Found world-writables files.", "$temp") if $temp;
    }
    
    foreach (@local_filesystems) {
	@temp =`find $_ -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -print 2>/dev/null`;
	foreach (@temp) {
	    chomp;
	    printOut("ERROR", "SUID/SGID file $_ is unauthorized (not part of any repo)") 
		if (`yum -C whatprovides $_ 2>/dev/null` =~ /No Matches found/);
	}
    }

    my $temp = `grep umask /etc/sysconfig/init`;
    printOut("INFO", "umask is not set to 027 in /etc/sysconfig/init. Note that umask is" . 
	 " set to 022 (for system accounts) and 002 for others in /etc/bashrc by default.")
	 if ($temp && !($temp =~ /^\s*umask\s+027\s*/));
	 
    printOut ("END", "$desc");
}

sub check_exploitprotection {
    my $desc = "Exploit protections like SELinux, Exec-shield, and ASLR. These settings either protect against zero-day exploits or make them really hard to succeed.";
    printOut ("BEGIN", "$desc");
    
    chomp(my $temp = `sysctl -n kernel.exec-shield`);
    printOut "ERROR", "ExecShield protection is not enabled. Set kernel.exec-shield = 1 in /etc/sysctl.conf." if ($temp != 1);

    chomp($temp = `sysctl -n kernel.randomize_va_space`);
    my $msg_desc = "ASLR protection is not enabled. Set kernel.randomize_va_space = 2 in /etc/sysctl.conf.";
    my $msg_detail = "The default value for this in RHEL5 is 1, and RHEL 6 set it to 2. Even in RHEL5 or CentOS5,\n";
    $msg_detail .= "you might want to consider setting this to 2. That is the most secure setting.";
    printOut ("ERROR", $msg_desc, $msg_detail) if ($temp != 2);

    $temp = fgrep ('^\\s*PRELINKING\\s*=\\s*yes', "/etc/sysconfig/prelink");    
    my $msg = "Disable it by setting PRELINKING=no in /etc/sysconfig/prelink.";
    printOut ("ERROR", "Prelinking is enabled. This will nullify ASLR. ", $msg ) if ($temp =~ /.*yes$/);
    
    chomp (my $_selinux_status = `/usr/sbin/sestatus`);
    
    printOut ("WARN", "SELinux is not enabled.", "") if ($_selinux_status !~ /SELinux status:\s+enabled/);
    $msg = "Modern RedHat EL and CentOS have SELinux in enforcing mode by default.";
    printOut ("WARN", "SELinux is not in enforcing mode during system runtime.", $msg) if ( $_selinux_status !~ /Current mode:\s+enforcing/);
    printOut ("WARN", "SELinux config is not set to 'enforce' mode during boot.", $msg) if ($_selinux_status !~ /Mode from config file:\s+enforcing/);
    
    printOut("END", "$desc");
}

sub check_useraccs() {
    my $desc = "User accounts, password quality and PAM.";
    printOut ("BEGIN", "$desc");
    
    # Root console logins
    my $temp = fgrep ('^console$|^vc\\/[0-9]+$|^tty[0-9]+$', "/etc/securetty", "inverse");
    chomp $temp;
    printOut "ERROR", "Root logins are not restricted to system console.", "Root can additionally login through: $temp" if $temp;
    printOut "SKIP", "Not running as root. Could not check if root logins are restricted to system consoles." if $is_normal_user;

    # Check which users can use su to login as root
    chomp ($temp = fgrep ('$wheel', "/etc/group"));
    my $msg = "Group 'wheel' must exist. It is used by both su and sudo to limit which users can become root.";
    printOut ("ERROR", "'wheel' group not found in /etc/group.", $msg) if $temp;
    chomp ($temp = fgrep ('^auth\\s+required\\s+pam_wheel.so\\s+use_uid',"/etc/pam.d/su"));
    my $msg_desc = "PAM module pam_wheel.so is not used. Anyone with root password can su to root.";
    my $msg_detail = "If this is used, then users not part of wheel group cannot 'su' to root, even if they know the root password. NOTE: Add atleast one user to wheel group before this is enabled. Otherwise, you will be locked out of root access completely on remote systems! This can happen because root logins are restricted only to system consoles, sshd root login is denied, and only wheel users can login as root. In /etc/pam.d/su, add or uncomment this line: auth    required    pam_wheel.so    use_uid";
    printOut ("ERROR", $msg_desc, $msg_detail) if ! $temp;
    
    # wheel group checks
    if (! $is_normal_user) {
	chomp (my $_wheel_passwd = fgrep( '^%wheel\s+ALL\=\(ALL\)\s+ALL$', "/etc/sudoers"));
	chomp (my $_wheel_nopasswd = fgrep( '^%wheel\s+ALL\=\(ALL\)\s+\(NOPASSWD\:\)\s+ALL$', "/etc/sudoers"));
	$msg_desc = "sudo is not configured to allow only users in wheel group to run root commands.";
	$msg_detail = "Add or uncomment the following line in /etc/sudoers: %wheel    ALL=(ALL)    ALL";
	printOut ("ERROR", $msg_desc, $msg_detail) if ((! $_wheel_passwd) && (! $_wheel_nopasswd));
	$msg_desc = "sudo is configured to allow wheel group users to run commands as root without supplying any password.";
	$msg_detail = "/etc/sudoers: %wheel    ALL=(ALL)  NOPASSWD: ALL. This setup is OK if the system has only passwordless key based logins.";
	printOut ("INFO", $msg_desc, $msg_detail);
	
    }
    else {
	$msg = "Could not check if sudo is configured to only allow user in wheel group to run ";
	$msg .= "root commands. Not running as root.";
	printOut "SKIP", $msg;
    }

    # /etc/passwd checks.
    open FILE, "/etc/passwd";
    my @acc_withshell;
    my @acc_noshell;
    my @acc_all;
    my @extra_root_accs;
    my @acc_emptyshell;
    
    while (<FILE>) {
	my @fields = split (/:/);
	push (@acc_all, $fields[0]);
	my $regex = '^/sbin/nologin$|^/bin/false$|^/dev/null$|^/sbin/shutdown$|^/sbin/halt$';
	if ($fields[6] !~ $regex) {
	    chomp $fields[6];
	    push (@acc_withshell,"$fields[0]:$fields[6]");
	    push (@acc_emptyshell, $fields[0]) if $fields[6] =~ /^\s*$/;
	}
	else {
	    push(@acc_noshell, $fields[0]);
	}
	printOut ("ERROR", "Non-root account has UID 0", "$fields[0]") if (($fields[2] == 0) && ($fields[0] ne "root"));	

    }
    close FILE;
    printOut ("WARN","Accounts that have valid login shell are:","@acc_withshell") if @acc_withshell;
    printOut ("ERROR", "Accounts have empty login shell. If login shell is empty, CentOS uses the system default shell." , "@acc_emptyshell") if @acc_emptyshell;

    # Check for locked accs and empty passwds.
    my @acc_locked;
    my @acc_emptypass;
    
    if (! $is_normal_user) {
        while (<@acc_all>) {
	    my @acc_stat = split (/ /, `passwd -S $_`);
	    push (@acc_emptypass, $_) if ($acc_stat[1] =~ /NP/);
	    push (@acc_locked, $_) if ($acc_stat[1] =~ /LK/);
        }
	
	my $msg = "The following accounts have 'locked' passwords. In some cases this means logins can happen via \n";
	$msg .= "other ways such as SSH keys, but not by using password.";
	printOut ("INFO", $msg, "@acc_locked") if @acc_locked;
	printOut("ERROR","The following accounts have empty password.", "@acc_emptypass") if @acc_emptypass;
	
	# Are there any accs with no login shell, but are not locked?
	my %locked_acc = map {$_=>1} @acc_locked;
	my @noshell_notlocked = grep (!defined $locked_acc{$_},@acc_noshell);
	
	$msg = "The following accounts are not locked, but have no login shell";
	printOut ("WARN", $msg, "@noshell_notlocked") if @noshell_notlocked;	
	
    }
    else {
	$msg = "Coudnt not check locked accounts and empty passwords. ";
	$msg .= "This script is not running as root.";
	printOut ("SKIP",$msg);
    }

    # Password expiry days
    $temp = fgrep ('^\\s*PASS_MAX_DAYS\\s+\\d', "/etc/login.defs");
    my @pass = split (/\s+/, $temp);
    $msg = "Password expiry is greater than 90 days. The current password expiry days is: $pass[1].";
    printOut ("ERROR", "$msg") if ($pass[1] > 90);
    
    # Min days allowed between passwd changes. 
    $temp = fgrep ('^\\s*PASS_MIN_DAYS\\s+\\d', "/etc/login.defs");
    @pass = split (/\s+/, $temp);
    $msg = "Passwords may be reused. Min days allowed between password changes is less than 7 days.";
    printOut ("WARN", "$msg", "The current setting is: $pass[1].") if ($pass[1] < 7);
    
    # Min password length. 
    $temp = fgrep ('^\\s*PASS_MIN_LEN\\s+\\d', "/etc/login.defs");
    @pass = split (/\s+/, $temp);
    $msg = "Min allowed length of password is less than 14 characters. On servers, minimum password length of 14 is recommended.";
    printOut ("ERROR", "$msg", "The current setting is: $pass[1]. Set PASS_MIN_LEN to 14 in /etc/login.defs.") if ($pass[1] < 14);
    
    # PAM cracklib checks for password quality
    my $cracklib_runs = fgrep ('^\\s*password\\s+(required|requisite)\\s+pam_cracklib.so\\s+', "/etc/pam.d/system-auth");
    chomp $cracklib_runs;
    
    if ($cracklib_runs) {
	$temp = fgrep ('^\\s*password\\s+required\\s+pam_cracklib.so\\s+', "/etc/pam.d/system-auth");
	$msg = "Change the pam_cracklib.so config in /etc/pam.d/system-auth from required to requisite.";
	printOut ("WARN", "PAM module cracklib must be run as 'requisite'.", $msg);

	# PAM password len checks
	$msg = "set minlen=14 on pam_cracklib.so config in /etc/pam.d/system-auth.";
	printOut ("ERROR", "Pam module cracklib does not enforce password min length 14.", $msg) if ($cracklib_runs !~ /minlen=14/);
	
	$msg = "PAM module cracklib is not configured to require at least one digit.";
	$msg_detail = "Set dcredit=-1 on pam_cracklib config in /etc/pamd./system-auth.";
	printOut ("ERROR", $msg, $msg_detail) if ($cracklib_runs !~ /dcredit=-1/);
	
	$msg = "PAM module cracklib is not configured to require at least one upper case letter.";
	$msg_detail = "Set ucredit=-1 on pam_cracklib config in /etc/pamd./system-auth.";
	printOut("ERROR", $msg, $msg_detail) if ($cracklib_runs !~ /ucredit=-1/);
	
	$msg = "PAM module cracklib is not configured to require at least one lower case letter.";
	$msg_detail = "Set lcredit=-1 on pam_cracklib config in /etc/pamd./system-auth.";
	printOut("ERROR", $msg, $msg_detail) if ($cracklib_runs !~ /lcredit=-1/);
	
	$msg = "PAM module cracklib is not configured to require at least one special character.";
	$msg_detail = "Set ocredit=-1 on pam_cracklib config in /etc/pamd./system-auth.";
	printOut("ERROR", $msg, $msg_detail) if ($cracklib_runs !~ /ocredit=-1/);
    }
    else {
	$msg = "Add this line to /etc/pam.d/system-auth";
	$msg .= "password\trequired\tpam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1";
        printOut ("ERROR", "Password quality checks are not enforced via pam_cracklib.", $msg );	
    }
    
    # Acc lockout based on failed login attempts by using PAM tally2
    my $auth_req = fgrep ('^\\s*auth\\s+required\\s+pam_tally2.so\\s+', "/etc/pam.d/system-auth"); chomp $auth_req;
    my $acc_req = fgrep ('^\\s*account\\s+required\\s+pam_tally2.so\\s+', "/etc/pam.d/system-auth"); chomp $acc_req;
    my $tally2_runs = $auth_req && $acc_req;

    if ($tally2_runs) {
	$msg = "Users accounts should be locked after 5 failures.";
	$msg_detail = "Set deny=5 on pam_tally2 \"auth required\" config line in /etc/pam.d/system-auth";
	printOut("ERROR", $msg, $msg_detail) if ($auth_req !~ /deny=5/);
	$msg = "Accounts should be locked for atleast 10 mins after failed logins.";
	$msg_detail = "Set unlock_time=600 on pam_tally2 \"auth required\" config line in /etc/pam.d/system-auth.";
	printOut ("ERROR",$msg,$msg_detail) if ($auth_req !~ /unlock_time=600/);
    }
    else {
	$msg = "To enable failed login account lockouts, add the following line to the top of auth lines in /etc/pam.d/system-auth:\n";
	$msg .= "auth\trequired\tpam_tally2.so deny=5 onerr=fail unlock_time=600\n";
	$msg .= "And add the following line to the top of account lines:\n";
	$msg .= "account\trequired\tpam_tally2.so";
        printOut ("ERROR", "User accounts are not locked based on number of failed login attempts.", $msg);	
    }
    
    # Are we using SHA 512 hashing?
    $temp = fgrep ('^\\s*password\\s+sufficient\\s+pam_unix.so\\s+.*(md5|bigcrypt|sha256|blowfish).*', "/etc/pam.d/system-auth"); chomp $temp;
    $msg = "PAM module pam_unix in /etc/pam.d/system-auth allows unsafe(md5,blowfish...) hash algorithm for passwords.";
    $msg_detail = "The \'password\tsufficient\tpam_unix.so\' line should only contain sha512. Remove other hash algorithms listed there.";
    printOut ("ERROR", $msg, $msg_detail) if $temp;
    

    $temp = fgrep ('^\\s*ENCRYPT_METHOD\\s+SHA512\\s*$', "/etc/login.defs"); chomp $temp;
    $msg = "Encryption method is not set to SHA512 in /etc/login.defs.";
    printOut ("ERROR", $msg, "Add line \'ENCRYPT_METHOD SHA512\' to /etc/login.defs.") if ! $temp;
    
    $temp = fgrep ('^\\s*MD5_CRYPT_ENAB\\s+no\\s*$', "/etc/login.defs"); chomp $temp;
    $msg = "MD5 is not explicitly disabled in /etc/login.defs.";
    printOut ("WARN", $msg, "Add line \'MD5_CRYPT_ENAB no\' to /etc/login.defs.") if ! $temp;
    
    $temp = fgrep ('^\\s*crypt_style\\s*=\s*sha512\\s*$', "/etc/libuser.conf"); chomp $temp;
    $msg = "SHA512 password hashing is not explicitly enabled in /etc/libuser.conf.";
    printOut ("ERROR", $msg, "Add/modify line \'crypt_style = sha512\' to /etc/libuser.conf.") if ! $temp;    
    
    printOut "END", "$desc";    
}

sub check_sshd() {
    my $desc = "SSH server configuration.";
    printOut ("BEGIN", "$desc");

    # *** Checking what runlevels sshd is on.
    my $sshd_status = `chkconfig --list sshd`;
    my $sshd_enabled = "";
    if ($sshd_status !~ /[35]:on/) {
	$sshd_enabled = "sshd is disabled in runlevels 3 and 5.";
    }
    else {
	$sshd_enabled = "sshd is enabled in runlevel(s):";
    	$sshd_enabled .= " 3" if ($sshd_status =~ /3:on/);
	$sshd_enabled .= " 5" if ($sshd_status =~ /5:on/);	
    }
    
    if ($sshd_enabled =~/enabled/) {
	printOut("INFO","$sshd_enabled");
    }
    else {
	printOut("INFO", "$sshd_enabled");
    }
    
    
    # *** Checking if sshd server configuration.
    if (! $is_normal_user) {
	# SSH protocol v1 is not secure	
	my $proto = fgrep ('^\\s*Protocol\s+.*1.*', "/etc/ssh/sshd_config");
	chomp $proto;
        printOut ("ERROR", "Protocol v1 is configured in /etc/ssh/sshd_config. Disable v1.") if $proto;
	
	# Which users can do remote ssh?
	my $allowed_ssh = fgrep('^\\s*(Allow|Deny)(Users|Groups)\\s+', "/etc/ssh/sshd_config");
	chomp $allowed_ssh;
	my $msg = "All local users in the system can login via ssh. It is good to explicitly ";
	$msg .= "restrict which local users can have remote ssh access. Use directives like AllowUsers.";
	my $msg_detail .= "Note: Whether root can directly login via ssh is checked later.";
	printOut ("INFO", $msg, $msg_detail) if ! $allowed_ssh;
	
	# Remote ssh client session timeouts
	my $ssh_timeout = fgrep('^\\s*ClientAlive(Interval|CountMax)\\s+', "/etc/ssh/sshd_config");
	chomp $ssh_timeout;
	$msg = "SSH idle timeouts are not set. Set ClientAliveInterval and ClientAliveCountMax directives.";
	printOut ("WARN", $msg) if ! $ssh_timeout;
	
	# Disable .rhosts file
	my $ssh_rhosts = fgrep('^\\s*IgnoreRhosts\\s+yes\\s+', "/etc/ssh/sshd_config");
	chomp $ssh_rhosts;
	$msg = "'IgnoreRhosts yes' directive is not set. Disable .rhosts based authentication.";
	printOut("ERROR", $msg) if ! $ssh_rhosts;
	
	# Disable direct root login via ssh.
	my $ssh_rootlogin = fgrep ('^\\s*PermitRootLogin\\s+no\\s+', "/etc/ssh/sshd_config");
	chomp $ssh_rootlogin;
	printOut ("ERROR", "Root logins are allowed via ssh. Disable it by using 'PermitRootLogin no'.") if ! $ssh_rootlogin;
	
	# Permit empty passwords? Default is no for RHEL[5,6] and CENTOS[5,6].
	# So just make sure that it is not turned on.
	my $ssh_emptypass = fgrep ('^\\s*PermitEmptyPasswords\\s+yes\\s+',"/etc/ssh/sshd_config");
	chomp $ssh_emptypass;
	printOut("ERROR","Empty passwords are allowed. Set PermitEmptyPasswords to yes.") if $ssh_emptypass;
	
	# Allow password based logins?
	my $ssh_passwdauth = fgrep ('^\\s*PasswordAuthentication\\s+no\\s+', "/etc/ssh/sshd_config");
	chomp $ssh_passwdauth;
	printOut ("WARN", "Disabling password based ssh auth is recommended. Use key based auth. Set 'PasswordAuthentication no' in /etc/ssh/sshd_config file.") if ! $ssh_passwdauth;
    }
    else {
	printOut ("SKIP", "Cannot check sshd server configuration. This script is not run as root.");	
    }
    
    printOut ("END", "$desc");
}

sub fgrep {
    open FILE, $_[1];
    my @contents = <FILE>;
    my @matches;
    @matches = grep {/$_[0]/} @contents if ! $_[2];
    @matches = grep {!/$_[0]/} @contents if ($_[2] eq "inverse");
    close FILE;
    return "@matches";
}

sub printscreen{
    print "ERROR: printscreen() received less than 2 parameters"  if (@_ < 2);
    if ($_[0] eq "BEGIN"){
	print "\n\n-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~\nStarting check: $_[1]";
    }
    elsif ($_[0] eq "END") {
	print "\tFinished check: $_[1]";
    }
    else {
	my $msg = $_[2];
	$msg =~ s/\n/\n\t\t/g;
	print "\t$_[0]: $_[1]";
	print "\t\t" . $msg if ($_[2] ne "");
    }
}

sub check_runningservices {
    my $desc = "Services started automatically on runlevels 3 or 5.";
    printOut ("BEGIN", "$desc");
    my $_msg_desc = "Disable any unwanted services from the list below.";
    my $_msg_detail = "";

    my @running = `chkconfig --list|awk -F' ' '{print \$1"#"\$5"#"\$7}'`;
    my @return_val;    
    while (<@running>) {
	next if ($_ !~ /3:on|5:on/);
	my @serv = split /#/;
	my ($run3, $run5) = "";
	$run3 = "3" if ($serv[1] =~ /3:on/);
	$run5 = "5" if ($serv[2] =~ /5:on/);
	my $result = sprintf ("%25s: %s %s\n",$serv[0], "$run3", "$run5");
	push (@return_val,$result);
    }

    printOut("INFO", $_msg_desc, "@return_val");
}

sub printhtml {
    # TODO
    # Function for HTML output.
}


sub writeHeaders {
    printOut ("BEGIN", "Host Information.");
    chomp (my $temp = `hostname`);
    printOut ("INFO", "Hostname:", "$temp");
    chomp ($temp = `dnsdomainname`);
    printOut ("INFO","Domain Name:", "$temp");
    chomp ($temp = `ip addr show`);
    printOut ("INFO", "Configured IPs", "$temp");
    chomp ($temp = `date`);
    printOut ("INFO", "Current System Date", $temp);
    if (! $is_normal_user) {
	chomp ($temp = `iptables -vnL`);
        printOut ("INFO", "Iptables Rules", $temp);	
    }
    else {
	printOut ("INFO", "Iptables Rules", "Cant check iptables rules. Please run the script as root.");
    }
    printOut ("END", "Host Information.");
}

sub writeFooters{
    # TODO
    # Function to write footers at the end of the audit report.
}

sub _validate_fw_policies{
	# Function to check fw default policies
	my $cmd = shift;
	# check if desired command exists
	`which $cmd &>/dev/null`;
	if ($? >> 8){
		printOut "ERROR", "$cmd not found - filtering may be not available", 
			"Install appropriate $cmd package and define proper firewall rules and policies";

	} else {
		my @net_iptables_policies=split "\n", `$cmd -vnL|grep policy`;
		foreach my $policy (@net_iptables_policies){
			if($policy =~ /Chain (\w+) \(policy ACCEPT/){
				printOut "WARN", "$cmd chain $1 is default policy ACCEPT should be DROP", 
					"Set default policy to DROP with '$cmd -P $1 DROP' command";
			}
		}
	}
}

sub _validate_sysctl{
	my $sysctl = shift;
	my $check_val = shift;
	my $cur_val = `sysctl -n $sysctl`;
	chomp $cur_val;
	my $hard_val = 'not-found';
	my $found = fgrep('^\s*'.$sysctl.'\s*=\s*'.$check_val.'\s*$', '/etc/sysctl.conf');
	if($found =~ /=\s*(.*)\s*$/){
		$hard_val = $1;
	}
	if ( $check_val ne $cur_val && $check_val ne $hard_val){
		printOut "ERROR", "$sysctl is set to $cur_val while $check_val is recommended", "use 'sysctl -w $sysctl=$check_val' to update runtime".
			" and append '$sysctl=$check_val' to /etc/sysctl.conf";
	} elsif ($check_val ne $cur_val && $check_val eq $hard_val) {
		printOut "WARN", "$sysctl is set to $cur_val in runtime while $check_val is recommended", 
			"use 'sysctl -w $sysctl=$check_val' to update runtime or reboot for persistent value to be loaded";
	} elsif ($check_val eq $cur_val && $check_val ne $hard_val) {
		printOut "WARN", "$sysctl is set to $cur_val, but different value in sysctl.conf [$hard_val]", 
			"append '$sysctl=$check_val' to /etc/sysctl.conf";
	}
}

