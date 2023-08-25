#!/usr/bin/perl -w

#
# Based on the Script found on http://blog.dest-unreach.be/2009/04/15/solarmax-maxtalk-protocol-reverse-engineered/comment-page-1#comment-1622
# by Niobos.
#
# Modified 2009-10-08/ cex (christian.exner at cex-development.de) to work with SolarMax 6000S over Ethernet.
#


use strict;
use warnings;

use POSIX;	# for TERMIOS calls
use Fcntl;	# for non-blocking IO

use Net::Ping;
use IO::Socket::INET;


#
# Some variables...
#
my $V_SM_IPADDR = "192.168.122.14";
my $V_SM_IPPORT = "12345";
my $V_SM_DEVICE_ADDR = "1";
my $V_SM_PING_TIMEOUT = 1; # seconds
my $V_SM_COMM_TIMEOUT = 5; # seconds

my $V_DEBUG = 0;
#my $V_DEBUG = 1;

my $V_SM_RESULT_COMMSTATE = "OFFLINE";
my $V_SM_RESULT_AC_POWER_NOW = 0;
my $V_SM_RESULT_AC_VOLTAGE_NOW = 0;
my $V_SM_RESULT_AC_CURRENT_NOW = 0;
my $V_SM_RESULT_DC_VOLTAGE_NOW = 0;
my $V_SM_RESULT_DC_CURRENT_NOW = 0;
my $V_SM_RESULT_AC_FREQ_NOW = 0;
my $V_SM_RESULT_POWER_INSTALLED = 0;
my $V_SM_RESULT_OPHOURS = 0;
my $V_SM_RESULT_STARTUPS = 0;
my $V_SM_RESULT_ENERGY_TODAY = 0;
my $V_SM_RESULT_ENERGY_YESTERDAY = 0;
my $V_SM_RESULT_ENERGY_MONTH_THIS = 0;
my $V_SM_RESULT_ENERGY_MONTH_LAST = 0;
my $V_SM_RESULT_ENERGY_YEAR_THIS = 0;
my $V_SM_RESULT_ENERGY_YEAR_LAST = 0;
my $V_SM_RESULT_ENERGY_TOTAL = 0;
my $V_SM_RESULT_PERCENT_LOAD_NOW = 0;
my $V_SM_RESULT_TEMP_HEAT_SINK_NOW = 0;
my $V_SM_RESULT_OPSTATE_TEXT = "";
my $V_SM_RESULT_SOFTWARE_VERSION = "";

my @cmd = (
	{ 'descr' => 'Address',			'name' => 'ADR', 'convert' => sub { return hex($_[0]); } }, # 0
	{ 'descr' => 'Type',			'name' => 'TYP', 'convert' => sub { return "0x" . $_[0]; } }, # 1
	{ 'descr' => 'Software version',	'name' => 'SWV', 'convert' => sub { return sprintf("%1.1f", hex($_[0]) / 10 ); } }, # 2
	{ 'descr' => 'Date day',		'name' => 'DDY', 'convert' => sub { return hex($_[0]); } }, # 3
	{ 'descr' => 'Date month',		'name' => 'DMT', 'convert' => sub { return hex($_[0]); } }, # 4
	{ 'descr' => 'Date year',		'name' => 'DYR', 'convert' => sub { return hex($_[0]); } }, # 5
	{ 'descr' => 'Time hours',		'name' => 'THR', 'convert' => sub { return hex($_[0]); } }, # 6
	{ 'descr' => 'Time minutes',		'name' => 'TMI', 'convert' => sub { return hex($_[0]); } }, # 7
	{ 'descr' => '???Error 1, number???',	'name' => 'E11', 'convert' => sub { return hex($_[0]); } }, # 8
	{ 'descr' => '???Error 1, day???',	'name' => 'E1D', 'convert' => sub { return hex($_[0]); } }, # 9
	{ 'descr' => '???Error 1, month???',	'name' => 'E1M', 'convert' => sub { return hex($_[0]); } }, # 10
	{ 'descr' => '???Error 1, hour???',	'name' => 'E1h', 'convert' => sub { return hex($_[0]); } }, # 11
	{ 'descr' => '???Error 1, minute???',	'name' => 'E1m', 'convert' => sub { return hex($_[0]); } }, # 12
	{ 'descr' => '???Error 2, number???',	'name' => 'E21', 'convert' => sub { return hex($_[0]); } }, # 13
	{ 'descr' => '???Error 2, day???',	'name' => 'E2D', 'convert' => sub { return hex($_[0]); } }, # 14
	{ 'descr' => '???Error 2, month???',	'name' => 'E2M', 'convert' => sub { return hex($_[0]); } }, # 15
	{ 'descr' => '???Error 2, hour???',	'name' => 'E2h', 'convert' => sub { return hex($_[0]); } }, # 16
	{ 'descr' => '???Error 2, minute???',	'name' => 'E2m', 'convert' => sub { return hex($_[0]); } }, # 17
	{ 'descr' => '???Error 3, number???',	'name' => 'E31', 'convert' => sub { return hex($_[0]); } }, # 18
	{ 'descr' => '???Error 3, day???',	'name' => 'E3D', 'convert' => sub { return hex($_[0]); } }, # 19
	{ 'descr' => '???Error 3, month???',	'name' => 'E3M', 'convert' => sub { return hex($_[0]); } }, # 20
	{ 'descr' => '???Error 3, hour???',	'name' => 'E3h', 'convert' => sub { return hex($_[0]); } }, # 21
	{ 'descr' => '???Error 3, minute???',	'name' => 'E3m', 'convert' => sub { return hex($_[0]); } }, # 22
	{ 'descr' => 'Operating hours',		'name' => 'KHR', 'convert' => sub { return hex($_[0]); } }, # 23
	{ 'descr' => 'Energy today [Wh]',	'name' => 'KDY', 'convert' => sub { return (hex($_[0]) * 100); } }, # 24
	{ 'descr' => 'Energy yesterday [Wh]',	'name' => 'KLD', 'convert' => sub { return (hex($_[0]) * 100); } }, # 25
	{ 'descr' => 'Energy this month [kWh]',	'name' => 'KMT', 'convert' => sub { return hex($_[0]); } }, # 26
	{ 'descr' => 'Energy last monh [kWh]',	'name' => 'KLM', 'convert' => sub { return hex($_[0]); } }, # 27
	{ 'descr' => 'Energy this year [kWh]',	'name' => 'KYR', 'convert' => sub { return hex($_[0]); } }, # 28
	{ 'descr' => 'Energy last year [kWh]',	'name' => 'KLY', 'convert' => sub { return hex($_[0]); } }, # 29
	{ 'descr' => 'Energy total [kWh]',	'name' => 'KT0', 'convert' => sub { return hex($_[0]); } }, # 30
	{ 'descr' => 'Language',		'name' => 'LAN', 'convert' => sub { return hex($_[0]); } }, # 31
	{ 'descr' => 'DC voltage [mV]',		'name' => 'UDC', 'convert' => sub { return (hex($_[0]) * 100); } }, # 32
	{ 'descr' => 'AC voltage [mV]',		'name' => 'UL1', 'convert' => sub { return (hex($_[0]) * 100); } }, # 33
	{ 'descr' => 'DC current [mA]',		'name' => 'IDC', 'convert' => sub { return (hex($_[0]) * 10); } }, # 34
	{ 'descr' => 'AC current [mA]',		'name' => 'IL1', 'convert' => sub { return (hex($_[0]) * 10); } }, # 35
	{ 'descr' => 'AC power [mW]',		'name' => 'PAC', 'convert' => sub { return (hex($_[0]) * 500); } }, # 36
	{ 'descr' => 'Power installed [mW]',	'name' => 'PIN', 'convert' => sub { return (hex($_[0]) * 500); } }, # 37
	{ 'descr' => 'AC power [%]',		'name' => 'PRL', 'convert' => sub { return hex($_[0]); } }, # 38
	{ 'descr' => 'Start ups',		'name' => 'CAC', 'convert' => sub { return hex($_[0]); } }, # 39
	{ 'descr' => '???',			'name' => 'FRD', 'convert' => sub { return "0x" . $_[0]; } }, # 40
	{ 'descr' => '???',			'name' => 'SCD', 'convert' => sub { return "0x" . $_[0]; } }, # 41
	{ 'descr' => '???',			'name' => 'SE1', 'convert' => sub { return "0x" . $_[0]; } }, # 42
	{ 'descr' => '???',			'name' => 'SE2', 'convert' => sub { return "0x" . $_[0]; } }, # 43
	{ 'descr' => '???',			'name' => 'SPR', 'convert' => sub { return "0x" . $_[0]; } }, # 44
	{ 'descr' => 'Temerature Heat Sink',	'name' => 'TKK', 'convert' => sub { return hex($_[0]); } }, # 45
	{ 'descr' => 'AC Frequency',		'name' => 'TNF', 'convert' => sub { return (hex($_[0]) / 100); } }, # 46
	{ 'descr' => 'Operation State',		'name' => 'SYS', 'convert' => sub { return hex($_[0]); } }, # 47
	{ 'descr' => 'Build number',		'name' => 'BDN', 'convert' => sub { return hex($_[0]); } }, # 48
	{ 'descr' => 'Error-Code(?) 00',	'name' => 'EC00', 'convert' => sub { return hex($_[0]); } }, # 49
	{ 'descr' => 'Error-Code(?) 01',	'name' => 'EC01', 'convert' => sub { return hex($_[0]); } }, # 50
	{ 'descr' => 'Error-Code(?) 02',	'name' => 'EC02', 'convert' => sub { return hex($_[0]); } }, # 51
	{ 'descr' => 'Error-Code(?) 03',	'name' => 'EC03', 'convert' => sub { return hex($_[0]); } }, # 52
	{ 'descr' => 'Error-Code(?) 04',	'name' => 'EC04', 'convert' => sub { return hex($_[0]); } }, # 53
	{ 'descr' => 'Error-Code(?) 05',	'name' => 'EC05', 'convert' => sub { return hex($_[0]); } }, # 54
	{ 'descr' => 'Error-Code(?) 06',	'name' => 'EC06', 'convert' => sub { return hex($_[0]); } }, # 55
	{ 'descr' => 'Error-Code(?) 07',	'name' => 'EC07', 'convert' => sub { return hex($_[0]); } }, # 56
	{ 'descr' => 'Error-Code(?) 08',	'name' => 'EC08', 'convert' => sub { return hex($_[0]); } }, # 57
);

# Operating Modes...
my @OPMODES = (
	{ 'mode' => '20001,0',		'descr_de' => '20001,0'},		# 0
	{ 'mode' => '20002,0',		'descr_de' => 'Zu wenig Einstrahlung'}, # 1
	{ 'mode' => '20003,0',		'descr_de' => 'Anfahren'}, 		# 2
	{ 'mode' => '20004,0',		'descr_de' => 'Betrieb auf MPP'}, 	# 3
	{ 'mode' => '20005,0',		'descr_de' => '20005,0'},		# 4
	{ 'mode' => '20006,0',		'descr_de' => '20006,0'},		# 5
	{ 'mode' => '20007,0',		'descr_de' => '20007,0'},		# 6
	{ 'mode' => '20008,0',		'descr_de' => 'Netzbetrieb'}, 		# 7
	{ 'mode' => '20009,0',		'descr_de' => '20009,0'},		# 8
);

# Device-Types...
my @DEVICETYPES = (
	{ 'type_hex' => '4E48',		'type_dec' => '20040',		'model' => 'SolarMax 6000S'},	# 0
);


sub checksum16 ($) {
# calculates the checksum 16 of the given string argument
	my @bytes = unpack("C*", $_[0]);
	my $sum = 0;
	foreach(@bytes) {
		$sum += $_;
		$sum %= 2**16;
	}
	return $sum;
}


sub mkmsg ($@) {
# makes a message with the items in the given array as questions
	my ($dst, @questions) = @_;

	my $src = 'FB';
	$dst = sprintf('%02X', $dst);
	my $len = '00';
	my $cs = '0000';
	my $msg = "64:" . join(';', @questions);
	
	$len = length("{$src;$dst;$len|$msg|$cs}");
	$len = sprintf("%02X", $len);
	
	$cs = checksum16("$src;$dst;$len|$msg|");
	$cs = sprintf("%04X", $cs);
	return "{$src;$dst;$len|$msg|$cs}";
}


sub waitfor ($$) {
# waits until $_[0] becomes readable
# timeout after $_[1] seconds
	my ($H, $timeout) = @_;
	my $rin = '';
	vec($rin, fileno($H), 1) = 1;
	my $found = select($rin, undef, undef, $timeout);	# block until readable
	return $found;
}


sub tryread ($$$) {
# tries hard to read $_[1] bytes from $_[0]
# timeout is $_[3];
# returns the result
	my ($H, $len, $timeout) = @_;
	my $buf = '';
	while( length($buf) < $len ) {
		# wait for something to happen
		if( ! waitfor($H, $timeout) ) {
			print "Timeout\n";
			return undef;
		}
		my $rv = sysread($H, $buf, $len-length($buf), length($buf));	# read the remaining bytes and put it in buf at the correct place
		if( !defined($rv) ) {
			die "Error reading: $!";
		}
		#print "read $rv bytes: $buf\n";
	}
	return $buf;
}


#
# Read Param from SolarMax...
#
sub getsmparam ($$$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $P_COMMAND) = @_;

   	my $V_MSG = mkmsg($P_DEVADDR, $P_COMMAND->{name});
	print STDERR "Writing \"$V_MSG\" to Socket\n" if $P_DEBUG;
	my $V_RV = syswrite ($P_HANDLE, $V_MSG);
	die("Write error: $!") unless $V_RV;
	die("Write incomplete") unless $V_RV == length($V_MSG);

	# Reading first 9 bytes
	print STDERR "Reading response header from Socket\n" if $P_DEBUG;
	$V_MSG = tryread($P_HANDLE, 9, $V_SM_COMM_TIMEOUT);
	next if !defined $V_MSG;
	print STDERR "Header received: \"$V_MSG\"\n" if $P_DEBUG;

	die("invalid response") unless $V_MSG =~ m/{([0-9A-F]{2});FB;([0-9A-F]{2})/;
	die("wrong source address: $1 != $V_SM_DEVICE_ADDR") unless hex($1) == $V_SM_DEVICE_ADDR;
	my $V_LEN = hex($2);

	print STDERR "Length is $V_LEN, reading rest\n" if $P_DEBUG;
	$V_LEN -= 9; # header is already in
	$V_MSG = tryread($P_HANDLE, $V_LEN, $V_SM_COMM_TIMEOUT);
	print STDERR "Read \"$V_MSG\"\n" if $P_DEBUG;

	die("invalid response") unless $V_MSG =~ m/^\|64:(\w{3})=([0-9A-F]+)\|([0-9A-F]{4})}$/;
	# TODO: check checksum
	die("wrong response") unless $1 eq $P_COMMAND->{'name'};

	return $P_COMMAND->{convert}($2);
}


#
# Get PAC/[W]...
#
sub get_sm_pac ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[36]);
	$V_RESULT = $V_RESULT / 1000;
	
	return $V_RESULT;
}


#
# Get UL1/[V]...
#
sub get_sm_ul1 ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[33]);
	$V_RESULT = $V_RESULT / 1000;
	
	return $V_RESULT;
}


#
# Get IL1/[A]...
#
sub get_sm_il1 ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[35]);
	$V_RESULT = $V_RESULT / 1000;
	
	return $V_RESULT;
}


#
# Get UDC/[V]...
#
sub get_sm_udc ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[32]);
	$V_RESULT = $V_RESULT / 1000;
	
	return $V_RESULT;
}


#
# Get IDC/[A]...
#
sub get_sm_idc ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[34]);
	$V_RESULT = $V_RESULT / 1000;
	
	return $V_RESULT;
}


#
# Get PIN/[W]...
#
sub get_sm_pin ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[37]);
	$V_RESULT = $V_RESULT / 1000;
	
	return $V_RESULT;
}


#
# Get CAC/[h]...
#
sub get_sm_cac ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[39]);
	
	return $V_RESULT;
}


#
# Get KDY/[kWh]...
#
sub get_sm_kdy ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[24]);
	
	return $V_RESULT;
}


#
# Get KLD/[kWh]...
#
sub get_sm_kld ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[25]);
	
	return $V_RESULT;
}


#
# Get KMT/[kWh]...
#
sub get_sm_kmt ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[26]);
	
	return $V_RESULT;
}


#
# Get KLM/[kWh]...
#
sub get_sm_klm ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[27]);
	
	return $V_RESULT;
}


#
# Get KYR/[kWh]...
#
sub get_sm_kyr ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[28]);
	
	return $V_RESULT;
}


#
# Get KLY/[kWh]...
#
sub get_sm_kly ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[29]);
	
	return $V_RESULT;
}


#
# Get KTO/[kWh]...
#
sub get_sm_kto ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[30]);
	
	return $V_RESULT;
}


#
# Get KHR/[h]...
#
sub get_sm_khr ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[23]);
	
	return $V_RESULT;
}


#
# Get PRL/[%]...
#
sub get_sm_prl ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[38]);
	
	return $V_RESULT;
}


#
# Get FRD...
#
sub get_sm_frd ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

#	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[40]);
	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[43]);
	
	return $V_RESULT;
}


#
# Get TKK...
#
sub get_sm_tkk ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[45]);
	
	return $V_RESULT;
}


#
# Get TNF...
#
sub get_sm_tnf ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[46]);
	
	return $V_RESULT;
}


#
# Get SYS (Operating-State)...
#
sub get_sm_sys ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	# !!! NOT WORKING YET !!!
	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[47]);
	
	return $V_RESULT;
}


#
# Get SWV/BDN (Software-Version + Build-Number)...
#
sub get_sm_swv ($$$$) {
	my ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG) = @_;

	my $V_RESULT = getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[2]);
	$V_RESULT = $V_RESULT.".".getsmparam ($P_HANDLE, $P_TIMEOUT, $P_DEVADDR, $P_DEBUG, $cmd[48]);

	return $V_RESULT;
}


#
# main()
#

# First PING Device to check whether it is online or not...
my $ping = Net::Ping->new("icmp");
my ($V_PING_RET, $V_PING_DURATION, $V_PING_IP) = $ping->ping($V_SM_IPADDR, $V_SM_PING_TIMEOUT);

if ($V_PING_RET) {
   # Device is responding...
   $V_SM_RESULT_COMMSTATE = "ONLINE";

   # Connect to Device and get some Data...
   my $V_SOCK = IO::Socket::INET->new (PeerAddr => $V_SM_IPADDR,
					PeerPort => $V_SM_IPPORT,
					Proto => 'tcp');
   if ($V_SOCK) {

	#
	# The following commands are working fine on SolarMax 6000S with Firmware 1.5.2066 over Ethernet...
	#

	# Get PAC...
	$V_SM_RESULT_AC_POWER_NOW = get_sm_pac ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);

	# Get UL1...
	$V_SM_RESULT_AC_VOLTAGE_NOW = get_sm_ul1 ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);
	
	# Get IL1...
	$V_SM_RESULT_AC_CURRENT_NOW = get_sm_il1 ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);
	
	# Get UDC...
	$V_SM_RESULT_DC_VOLTAGE_NOW = get_sm_udc ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);
	
	# Get IDC...
	$V_SM_RESULT_DC_CURRENT_NOW = get_sm_idc ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);

	# Get PIN...
	$V_SM_RESULT_POWER_INSTALLED = get_sm_pin ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);

	# Get TNF...
	$V_SM_RESULT_AC_FREQ_NOW = get_sm_tnf ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);
	
	# Get KHR
	$V_SM_RESULT_OPHOURS = get_sm_khr ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);
	
	# Get CAC
	$V_SM_RESULT_STARTUPS = get_sm_cac ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);
	
	# Get KDY
	$V_SM_RESULT_ENERGY_TODAY = get_sm_kdy ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);
	
	# Get KLD
	$V_SM_RESULT_ENERGY_YESTERDAY = get_sm_kld ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);
	
	# Get KMT
	$V_SM_RESULT_ENERGY_MONTH_THIS = get_sm_kmt ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);
	
	# Get KLM
	$V_SM_RESULT_ENERGY_MONTH_LAST = get_sm_klm ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);
	
	# Get KYR
	$V_SM_RESULT_ENERGY_YEAR_THIS = get_sm_kyr ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);
	
	# Get KLY
	$V_SM_RESULT_ENERGY_YEAR_LAST = get_sm_kly ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);

	# Get PRL
	$V_SM_RESULT_PERCENT_LOAD_NOW = get_sm_prl ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);
	
	# Get KTO...
	$V_SM_RESULT_ENERGY_TOTAL = get_sm_kto ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);

	# Get TKK...
	$V_SM_RESULT_TEMP_HEAT_SINK_NOW = get_sm_tkk ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);

	# Get SYS...
	#$V_SM_RESULT_OPSTATE_TEXT = get_sm_sys ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);

	# Get SWV+BDN...
	$V_SM_RESULT_SOFTWARE_VERSION = get_sm_swv ($V_SOCK, $V_SM_COMM_TIMEOUT, $V_SM_DEVICE_ADDR, $V_DEBUG);

	close($V_SOCK);
   } else {
	# Communication failure...
	$V_SM_RESULT_COMMSTATE = "COMMFAIL";
	$V_SM_RESULT_AC_POWER_NOW = 0;
	$V_SM_RESULT_AC_VOLTAGE_NOW = 0;
	$V_SM_RESULT_AC_CURRENT_NOW = 0;
	$V_SM_RESULT_DC_VOLTAGE_NOW = 0;
	$V_SM_RESULT_DC_CURRENT_NOW = 0;
	$V_SM_RESULT_AC_FREQ_NOW = 0;
	$V_SM_RESULT_POWER_INSTALLED = 0;
	$V_SM_RESULT_OPHOURS = 0;
	$V_SM_RESULT_STARTUPS = 0;
	$V_SM_RESULT_ENERGY_TODAY = 0;
	$V_SM_RESULT_ENERGY_YESTERDAY = 0;
	$V_SM_RESULT_ENERGY_MONTH_THIS = 0;
	$V_SM_RESULT_ENERGY_MONTH_LAST = 0;
	$V_SM_RESULT_ENERGY_YEAR_THIS = 0;
	$V_SM_RESULT_ENERGY_YEAR_LAST = 0;
	$V_SM_RESULT_ENERGY_TOTAL = 0;
	$V_SM_RESULT_PERCENT_LOAD_NOW = 0;
	$V_SM_RESULT_TEMP_HEAT_SINK_NOW = 0;
	$V_SM_RESULT_OPSTATE_TEXT = "";
	$V_SM_RESULT_SOFTWARE_VERSION = "";
   }
} else {
   # Device is offline...

}
$ping->close();


# Write Results to Console...
print "COMMUNICATION...............: $V_SM_RESULT_COMMSTATE\n";
print "AC Power now.........[Watt].: $V_SM_RESULT_AC_POWER_NOW\n";
print "Load now................[%].: $V_SM_RESULT_PERCENT_LOAD_NOW\n";
print "AC Voltage now.......[Volt].: $V_SM_RESULT_AC_VOLTAGE_NOW\n";
print "AC Current now.......[Amps].: $V_SM_RESULT_AC_CURRENT_NOW\n";
print "DC Voltage now.......[Volt].: $V_SM_RESULT_DC_VOLTAGE_NOW\n";
print "DC Current now.......[Amps].: $V_SM_RESULT_DC_CURRENT_NOW\n";
print "Power installed......[Watt].: $V_SM_RESULT_POWER_INSTALLED\n";
print "AC Frequency now.......[Hz].: $V_SM_RESULT_AC_FREQ_NOW\n";
print "Operating Hours.........[h].: $V_SM_RESULT_OPHOURS\n";
print "Startups....................: $V_SM_RESULT_STARTUPS\n";
print "Energy today...........[Wh].: $V_SM_RESULT_ENERGY_TODAY\n";
print "Energy yesterday.......[Wh].: $V_SM_RESULT_ENERGY_YESTERDAY\n";
print "Energy this Month.....[kWh].: $V_SM_RESULT_ENERGY_MONTH_THIS\n";
print "Energy last Month.....[kWh].: $V_SM_RESULT_ENERGY_MONTH_LAST\n";
print "Energy this Year......[kWh].: $V_SM_RESULT_ENERGY_YEAR_THIS\n";
print "Energy last Year......[kWh].: $V_SM_RESULT_ENERGY_YEAR_LAST\n";
print "Energy total..........[kWh].: $V_SM_RESULT_ENERGY_TOTAL\n";
print "Temperature Heat Sink..[°C].: $V_SM_RESULT_TEMP_HEAT_SINK_NOW\n";
print "Operational State...........: $V_SM_RESULT_OPSTATE_TEXT\n";
print "Software-Version............: $V_SM_RESULT_SOFTWARE_VERSION\n";


exit(0);
