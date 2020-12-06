#!/usr/bin/perl
#
# This file is AddOn of the IPCop Firewall.
#
# IPCop is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# IPCop is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IPCop.  If not, see <http://www.gnu.org/licenses/>.
#
# (c) 2008-2014, the IPCop team
#
# $Id: iptraffic.pl, v0.6 2015-12-29 15:49:00 RadioCarbon $
#

use strict;
use DBI;
use RRDs;
use Socket;
use Fatal qw/ open /;

require '/var/ipfire/general-functions.pl';
require '/var/ipfire/lang.pl';

my $debug;
my $version		= 'v0.8';
my $gruppe		= getgrnam("nobody");
my $user		= getpwnam("nobody");
my $FW 			= '/sbin/iptables';
my $logdir		= "/var/log/iptraffic";
my $addondir	= "/var/ipfire/iptraffic";
my $ipadrfile	= "$logdir/iptraffic";
my $iptrafficdb	= "$logdir/iptraffic.db";
my $IPTrafficTable = "IPTraffic";
my $iptconfig	= "$addondir/iptraffic.conf";
my $rrdimgdir	= "/srv/web/ipfire/html/graphs/iptraffic";
my $rrddir		= "/var/log/rrd/iptraffic";
my ($Sekunden, $Minuten, $Stunden, $Monatstag, $Monat, $Jahr, $Wochentag, $Jahrestag, $Sommerzeit) = localtime(time);
my $heute = sprintf("%4d%02d%02d", $Jahr+1900, ++$Monat, $Monatstag);
($Sekunden, $Minuten, $Stunden, $Monatstag, $Monat, $Jahr, $Wochentag, $Jahrestag, $Sommerzeit) = localtime(time - 86400);
my $gestern = sprintf("%4d%02d%02d", $Jahr+1900, ++$Monat, $Monatstag);

foreach (@ARGV) {
	if ( $_ eq '-d' || $_ eq '--debug') { $debug = 1; }
	if ( $_ eq '-h' || $_ eq '--help' ) { print help(); exit 1; }
}

if ($debug == 1){
	if ($Minuten % 5 == 0 ) {
		print "30s warten, Cronjob aktiv\n";
		sleep (30);
	}
	startdebug();
}

# read from iptables
my $a_output = `$FW -nvx -L CUSTOMOUTPUT`;
my $a_fwdout = `$FW -nvx -L CUSTOMFORWARD`;
my $a_input = `$FW -nvx -L CUSTOMINPUT`;

# extract Traffic from iptables
my %output = extractTraffic($a_output);
my %fwdout = extractTraffic($a_fwdout);
my %fwdin = extractTraffic($a_fwdout);
my %input = extractTraffic($a_input);

# create/check Table in DB
my $dbh = DBI->connect("dbi:SQLite:dbname=$iptrafficdb", "", "", {RaiseError => 1});
my $sql = "CREATE TABLE IF NOT EXISTS '".$IPTrafficTable."'(client VARCHAR(16), hostname VARCHAR(25) default NULL, date INT UNSIGNED, input INT UNSIGNED, output INT UNSIGNED, traflimit INT UNSIGNED, port INT UNSIGNED);";
my $Statement = $dbh->prepare($sql);
$Statement->execute();
$Statement->finish();

my @iptclients = getIPTrafficClientlist($heute, $gestern);
#print "Clients: ".@iptclients."\n";
foreach (sort @iptclients){
	chomp;
	my ($clientIP, $hostname) = '';
	my ($date, $clientoutput, $clientinput, $traflimit) = 0;
	my @buffer = ();
	($clientIP, $hostname, $date, $clientinput, $clientoutput, $traflimit) =  split( /,/, $_ );

	if (trim($traflimit) eq 'DEL') {
		clientDelete($clientIP);
		if ($debug == 1){print "Client $clientIP deleted \n";}
		next;
	}
	if ($date < $heute) {next;};

	# not Line in iptables: create item and set starttraffic = 0
	unless (exists($output{$clientIP})) { `$FW -A CUSTOMOUTPUT -d $clientIP -j RETURN`; $output{$clientIP} = 0;}
	unless (exists($fwdout{$clientIP})) { `$FW -A CUSTOMFORWARD -d $clientIP -j RETURN`; $fwdout{$clientIP} = 0;}
	unless (exists($fwdin{$clientIP})) { `$FW -A CUSTOMFORWARD -s $clientIP -j RETURN`; $fwdin{$clientIP} = 0;}
	unless (exists($input{$clientIP})) { `$FW -A CUSTOMINPUT -s $clientIP -j RETURN`; $input{$clientIP} = 0;}

	if ($debug == 1){printf ("%15s%15s%15s%15s%15s%15s%15s\n", $clientIP, $output{$clientIP}, $input{$clientIP}, $fwdout{$clientIP}, $fwdin{$clientIP}, $output{$clientIP}+$fwdout{$clientIP}, $input{$clientIP}+$fwdin{$clientIP});}
	
	updateTrafficCount($clientIP, $hostname, $heute, $input{$clientIP}+$fwdin{$clientIP}, $output{$clientIP}+$fwdout{$clientIP}, $traflimit);
	updateiptrafficdata($clientIP, $input{$clientIP}+$fwdin{$clientIP}, $output{$clientIP}+$fwdout{$clientIP});

	$hostname = ($hostname eq '') ? $clientIP : $hostname;
	if ( -e "$rrddir/$clientIP.rrd" ) {
		updateiptrafficgraph("$clientIP", "$hostname", "hour");
		updateiptrafficgraph("$clientIP", "$hostname", "day");
		updateiptrafficgraph("$clientIP", "$hostname", "week");
		updateiptrafficgraph("$clientIP", "$hostname", "month");
		updateiptrafficgraph("$clientIP", "$hostname", "year");
	}
}

$dbh->disconnect() or warn $dbh->errstr;

sub getIPTrafficClientlist{
	my $heute = shift;
	my $gestern = shift;
	my $clientIP;
	my $hostname = '';
	my $date = 0;
	my $output = 0;
	my $input = 0;
	my $traflimit = 0;
	my $port = 0;
	my $trafficReset = 0;
	my $clientIPfirst = '';
	my @clientlist = '';
	
	my $sql = "SELECT * FROM '".$IPTrafficTable."' WHERE date = '".$heute."' OR date = '".$gestern."' ORDER by date DESC;";
#	print "SQL: $sql \n";
	$Statement = $dbh->prepare($sql);
	$Statement->bind_columns(\$clientIP, \$hostname, \$date, \$input, \$output, \$traflimit, \$port);
	$Statement->execute();
	while( $Statement->fetch()){
		my $sql = "SELECT COUNT(*) FROM `".$IPTrafficTable."` WHERE `client` = '".$clientIP."' AND `date` = '".$heute."';";
		my $cStatement = $dbh->prepare($sql);
		$cStatement->execute;
		my $count = $cStatement->fetchrow;
		$cStatement->finish();

		unless ( $count > 0){
			$sql = "INSERT INTO '".$IPTrafficTable."' (`client`, `hostname`, `date`, `input`, `output`, `traflimit`) VALUES ( '".$clientIP."', '".$hostname."', '".$heute."', '".$input."', '".$output."', '".$traflimit."');";
			my $Insert= $dbh->prepare($sql);
			$Insert->execute();
			$Insert->finish();
			$trafficReset = 1;
		}
#		print "getIPTrafficClientListe: $clientIP, $hostname, $date, $input, $output, $traflimit \n";
		push (@clientlist, "$clientIP, $hostname, $date, $input, $output, $traflimit \n");
	}
	$Statement->finish();

	# daily reset count traffic
	if ( $trafficReset == 1) {
		my $reset;
		$reset = `$FW -Z CUSTOMFORWARD`;
		$reset = `$FW -Z CUSTOMOUTPUT`;
		$reset = `$FW -Z CUSTOMINPUT`;
	}
	return @clientlist;
}

sub updateTrafficCount {
	my $client = shift;
	my $hostname = shift;
	my $date = shift;
	my $input = shift;
	my $output = shift;
	my $traflimit = shift;

	$hostname = (length($hostname) <= 2) ? gethostbyaddr(inet_aton($client), AF_INET) : $hostname;

	my $sql = "UPDATE '".$IPTrafficTable."' SET `client` = '".$client."', `hostname` = '".trim($hostname)."', `input` = '".$input."', `output` = '".$output."', `traflimit` = '".trim($traflimit)."' WHERE `client` = '".$client."' AND `date` = '".$date."';";
	my $Update = $dbh->prepare($sql);
	$Update->execute();
	$Update->finish();
}

sub updateiptrafficdata {
	my $ip = $_[0];
	my $incoming = $_[1];
	my $outgoing = $_[2];

	if ( !-e "$rrddir/$ip.rrd" ) {
		RRDs::create(
			"$rrddir/$ip.rrd",						"--step=300",
			"DS:incoming:DERIVE:600:0:125000000",	"DS:outgoing:DERIVE:600:0:125000000",
			"RRA:AVERAGE:0.5:1:576",				"RRA:AVERAGE:0.5:6:672",
			"RRA:AVERAGE:0.5:24:732",				"RRA:AVERAGE:0.5:144:1460"
		);
		my $ERROR = RRDs::error;
		print "Error in RRD::create for IP-Traffic: $ERROR\n" if $ERROR;
	}

	RRDs::update("$rrddir/$ip.rrd", "-t", "incoming:outgoing", "N:$incoming:$outgoing");

	chown($user, $gruppe, "$rrddir/$ip.rrd");

	my $error = RRDs::error;
	if ($error) { &General::log("iptraffic","$error"); }
}

sub updateiptrafficgraph {
	my $ip = $_[0];
	my $client = $_[1];
	my $period = $_[2];

	RRDs::graph(
		"$rrdimgdir/$ip-$period.png",
		"--start", "-1$period",	"-aPNG", "-i", "-z",
		"--alt-y-grid", "-w 600", "-h 100",
		"--font", "TITLE:0:sans mono bold oblique",
		"--pango-markup",
		"--interlaced",
		"--color", "SHADEA#E0E0E0",
		"--color", "SHADEB#E0E0E0",
		"--color", "BACK#E0E0E0",
		"-t $client $Lang::tr{'graph per'} ($Lang::tr{$period})",
		"DEF:incoming=$rrddir/$ip.rrd:incoming:AVERAGE",
		"DEF:outgoing=$rrddir/$ip.rrd:outgoing:AVERAGE",
		"CDEF:incomingbits=incoming,8,*",
		"CDEF:outgoingbits=outgoing,8,*",
		"CDEF:outgoingnegbits=outgoing,-8,*",
		"HRULE:0#000000",
		"AREA:incomingbits#00FF00:$Lang::tr{'incoming traffic in bits per second'}\\j",
		"GPRINT:incomingbits:MAX:$Lang::tr{'maximal'}\\:%8.3lf %sbps",
		"GPRINT:incomingbits:AVERAGE:$Lang::tr{'average'}\\:%8.3lf %sbps",
		"GPRINT:incomingbits:LAST:$Lang::tr{'current'}\\:%8.3lf %sbps\\j",
		"AREA:outgoingnegbits#0000FF:$Lang::tr{'outgoing traffic in bits per second'}\\j",
		"GPRINT:outgoingbits:MAX:$Lang::tr{'maximal'}\\:%8.3lf %sbps",
		"GPRINT:outgoingbits:AVERAGE:$Lang::tr{'average'}\\:%8.3lf %sbps",
		"GPRINT:outgoingbits:LAST:$Lang::tr{'current'}\\:%8.3lf %sbps\\j",
		@{&rrd_lastupdate()}
	);
	chown($user, $gruppe, "$rrdimgdir/$ip-$period.png");
	
	my $ERROR = RRDs::error;
	print "Error in RRD::create for IP-Traffic: $ERROR\n" if $ERROR;

	my $error = RRDs::error;

	if ($error) { &General::log("iptraffic","$error"); }
}

sub rrd_lastupdate {
	my $result  = [];

	push @$result, "COMMENT:<span size='smaller'> </span>\\r";
	push @$result, "COMMENT:<span size='smaller'>Last update\\: ". RRDescape(scalar localtime()) ."</span>\\r";

	return $result;
}
# This from munin-graph which is: Copyright (C) 2002-2004 Jimmy Olsen, Audun Ytterdal
# Munin has some pretty cool RRD graphing.
sub RRDescape {
	my $text = shift;
	return undef if not defined $text;
	$text =~ s/\\/\\\\/g;
	$text =~ s/:/\\:/g;
	return $text;
}

sub clientDelete {
	my $client = shift;
	my @ok = ();
	# remove client item from iptables
	$ok[0] = `$FW -D CUSTOMOUTPUT -d $client -j RETURN`;
	$ok[1] = `$FW -D CUSTOMINPUT -s $client -j RETURN`;
	$ok[2] = `$FW -D CUSTOMFORWARD -d $client -j RETURN`;
	$ok[3] = `$FW -D CUSTOMFORWARD -s $client -j RETURN`;

	# remove client graphs
	$ok[4] = unlink ("$rrdimgdir/$client-*");

	# remove client rrd-file
	$ok[5] = unlink ("$rrddir/$client.rrd");

	# remove client from database
	my $sql = "DELETE FROM `".$IPTrafficTable."` WHERE `client` = '".$client."';";
	my $Delete = $dbh->prepare($sql);
	$Delete->execute();
	$Delete->finish();
}

sub extractTraffic {
	my $page = shift;
	my %clientHash;
	my @buffer;
	my @line = split('\n',$page);
	foreach (sort @line){
		chomp;
		@buffer = split(/\s+/, trim($_));
		if ($buffer[0] eq 'pkts' || $buffer[0] eq 'Chain') {next;};
#		print "0: $buffer[0] 1: $buffer[1] 2: $buffer[2] 3: $buffer[3] 4: $buffer[4] 5: $buffer[5] 6: $buffer[6] 7: $buffer[7] 8: $buffer[8] \n";
		$clientHash{"$buffer[7]"} = $buffer[1];
		$clientHash{"$buffer[8]"} = $buffer[1];
		if (exists $clientHash{'0.0.0.0/0'}) {delete $clientHash{'0.0.0.0/0'};}
	}
	return %clientHash;
}

sub trim {
	my $str = shift;
	$str =~ s/^\s+|\s+$//g;
	return $str;
}

sub startdebug {

printf "
Hole Traffic von iptables ...

%15s%15s%15s%15s%15s%15s%15s
----------------------------------------------------------------------------------------------------------
", "IP-Adresse", "IN", "OUT", "FWD IN", "FWD OUT", "Sum IN", "Sum OUT";
}

sub help {
	return "
IPTraffic $version
Created 2014/2019 by Frank Mainz (RadioCarbon)
mail: ipfire\@cybermainzel.de

use option -d or --debug for debugging
use option -h or --help for help\n\n";
}
