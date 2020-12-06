#!/usr/bin/perl
###############################################################################
#                                                                             #
# IPFire.org - A linux based firewall                                         #
# Copyright (C) 2007  Michael Tremer & Christian Schmidt                      #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or           #
# (at your option) any later version.                                         #
#                                                                             #
# This program is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
# GNU General Public License for more details.                                #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
###############################################################################
#
#
# This file is AddOn of the IPFire Firewall base on IPCop-Addon IPTraffic
#
# $Id: iptraffic.cgi, v0.8 2020-12-05 23:27:00 RadioCarbon $
#

# Add entry in menu
# MENUENTRY status 065 "IPTraffic" "IPTraffic"


my $debug	= 0;
# enable only the following on debugging purpose
use warnings;
use strict;
# needs Perl-DBI-Addon
use DBI;
use Carp ();
use CGI::Carp 'fatalsToBrowser';
use Socket;
use Fatal qw/ open /;

require '/var/ipfire/general-functions.pl';
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";

my $version = 'v0.7';

my @line;
my @iptclients;
my @get_param;
my @devs_net;
my ( %ips, %arpcache, %iptsettings, %netsettings ) = ();

my $idarp;
my $enabled_count = 0;
my $IPTrafficTable = "IPTraffic";

my $graphdir	= '/graphs/iptraffic';
my $imgsys		= "/images";
my $imgstatic	= "$imgsys/iptraffic";
my $logfile		= "/var/log/iptraffic/iptraffic";
my $rrdimgdir	= "/srv/web/ipfire/html/graphs/iptraffic";
my $rrddir		= "/var/log/rrd/iptraffic";
my $iptrafficdb	= "/var/log/iptraffic/iptraffic.db";

## some iptraffic settings
$iptsettings{'ACTION'} = '';
$iptsettings{'SORT'} = '';
$iptsettings{'PARAM'} = '';
$iptsettings{'CLIENTNAME'} = '';

my $contents = $ENV{'QUERY_STRING'};

&Header::getcgihash(\%iptsettings);
&General::readhash('/var/ipfire/ethernet/settings', \%netsettings);
#if (-e '/var/ipfire/addons/xtiface/xtiface.conf') {
#	&General::readhash('/var/ipfire/addons/xtiface/xtiface.conf', \%netsettings);
#}

# add client to list
if ($iptsettings{'ACTION'} eq 'add'){
	my $client = $iptsettings{'PARAM'};
	my $name = $iptsettings{'HOST'};
	setClientAction($client,'ADD',$name);
	siteReload();
}
# delete client from list
if ($iptsettings{'ACTION'} eq 'del'){
	my $client = $iptsettings{'PARAM'};

	setClientAction($client,'DEL');
	siteReload();
}
# set trafficlimit on
if ($iptsettings{'ACTION'} eq 'ON'){
	my $client = $iptsettings{'PARAM'};

	setClientAction($client,'ON');
#	siteReload();
}
# set trafficlimit off
if ($iptsettings{'ACTION'} eq 'OFF'){
	my $client = $iptsettings{'PARAM'};

	setClientAction($client,'OFF');
#	siteReload();
}
# set sort direction
if ($contents) {
	@get_param = split(/=/,$contents);
	$iptsettings{'SORT'} = $get_param[1];
}

&Header::showhttpheaders();
&Header::openpage('IPTraffic', 1, '');
#&Header::openpage($Lang::tr{'IPTraffic'}, 1, '');
&Header::openbigbox('100%', 'left');

#########################################################
# START DEBUG DEBUG
if ($debug) {
	&Header::openbox('100%', 'left', 'DEBUG');
	my $debugCount = 0;
	foreach my $line (sort keys %iptsettings) {
		print "$line = $iptsettings{$line}<br />\n";
		$debugCount++;
	}
	print "&nbsp;Count: $debugCount <br>\n";
	print "&nbsp;Contents: $contents<br>";
	print "&nbsp;Get-param: @get_param<br>";
	
	hrline();

	my $netdebug = 0;
	foreach (sort keys %netsettings) {
		print"$_ = $netsettings{$_}<br />\n";
		$netdebug++;
	}
	&Header::closebox();
}
# END DEBUG DEBUG
#########################################################

### Call funktions, default List with Arplist
if ($iptsettings{'ACTION'} eq 'GRAPH'){
	disp_singleclient();
}
else{
#	disp_config();
	disp_clientlist();
	disp_arp();
}

&Header::closebigbox();
&Header::closepage();

#########################################################
# subroutines

### reload self
sub siteReload {
	print "Status: 302 Found\n";
	print "Location: $ENV{'SCRIPT_NAME'}\n";
	print "URI: <$ENV{'SCRIPT_NAME'}>\n";
	print "Content-type: text/html\r\n\r\n";
}

### display config area
sub disp_config {
	my $title = 'Konfiguration';

	&Header::openbox('100%', 'left', "$title Titel");
		print <<END
<table width='100%' align='center' border="1">
	<tr>
		<td width="5%">&nbsp;</td>
		<td>Device to limit:</td>
		<td>Device max(MBit/sek):</td>
		<td>Device limit(kBit/sek):</td>
		<td width="15%">Version: $version</td>
	</tr>
</table>
END
;
	&Header::closebox();
}

### display single client graphs
sub disp_singleclient {
	my $client = $iptsettings{'PARAM'};
	my $title = '';
	my $host = $iptclients[$client];

	$title = $Lang::tr{'test'} if ($host eq 'test');

	my $back = "<a href='$ENV{'SCRIPT_NAME'}'>";

	&Header::openbox('100%', 'center', "$title $Lang::tr{'graph'}");

	if (-e "$rrdimgdir/$client-day.png") {
		print <<END
<table width='100%'>
	<tr>
		<td width='10%'>$back<img src='$imgsys/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
		<td>&nbsp;</td>
	</tr>
</table>
<hr />
<img src='$graphdir/$client-hour.png' border='0' alt='$host-$Lang::tr{'hour'}' /><hr />
<img src='$graphdir/$client-day.png' border='0' alt='$host-$Lang::tr{'day'}' /><hr />
<img src='$graphdir/$client-week.png' border='0' alt='$host-$Lang::tr{'week'}' /><hr />
<img src='$graphdir/$client-month.png' border='0' alt='$host-$Lang::tr{'month'}' /><hr />
<img src='$graphdir/$client-year.png' border='0' alt='$host-$Lang::tr{'year'}' />
<hr />
<table width='100%'><tr>
	<td width='10%'>$back<img src='$imgsys/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
	<td>&nbsp;</td>
</tr></table>
END
;
	}
	else {
		print <<END
<table width='100%'>
	<tr>
		<td width='10%'>$back<img src='$imgsys/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
		<td>&nbsp;</td>
	</tr>
</table>
<hr />
<table width='100%' align='center'>
	<tr><td>&nbsp;</td></tr>
	<tr><td>Grafik:$rrdimgdir/$client-day.png nicht gefunden</td></tr>
	<tr><td align='center'>$Lang::tr{'no information available'}</td></tr>
	<tr><td>&nbsp;</td></tr>
</table>
END
;
	}
	&Header::closebox();
}

sub disp_clientlist {
	my ($sortarrowip, $sortarrowhn, $sortarrowou, $sortarrowouM, $sortarrowouW, $sortarrowouD, $sortarrowin, $sortarrowinM, $sortarrowinW, $sortarrowinD);
	my ($sum_incoming_all, $sum_incoming_month, $sum_incoming_week, $sum_incoming_day) = 0;
	my ($sum_outgoing_all, $sum_outgoing_month, $sum_outgoing_week, $sum_outgoing_day) = 0;
	my ($ipsort, $hnsort, $insort, $ousort, $insortM, $ousortM, $insortW, $ousortW, $insortD, $ousortD);
	my $count = 0;
	my @sorted_ip = '';
	my %traffic = getAllTrafficFromTable();
	my %ips = getIPfromTable();
	my $sort = $iptsettings{'SORT'};
	chomp $sort;
	if (length($sort) < 1) { $sort = 'IPup'; }
	
	$ipsort = 'IPdown';
	$hnsort = 'HNdown';
	$insort = 'INdown';
	$ousort = 'OUdown';
	$insortM = 'INdownM';
	$ousortM = 'OUdownM';
	$insortW = 'INdownW';
	$ousortW = 'OUdownW';
	$insortD = 'INdownD';
	$ousortD = 'OUdownD';
	
	SWITCH: {
		if ($sort eq 'IPup') {
			$sortarrowip = '&nbsp;&#9650;';
			$ipsort = 'IPdown';
			@sorted_ip = map {sprintf "%d.%d.%d.%d", split /[,.]/} sort map {sprintf "%03d.%03d.%03d.%03d", split /[,.]/} %ips;
			last SWITCH;
		}
		if ($sort eq 'IPdown') {
			$sortarrowip = '&nbsp;&#9660;';
			$ipsort = 'IPup';
			@sorted_ip = map {sprintf "%d.%d.%d.%d", split /[,.]/} reverse sort map {sprintf "%03d.%03d.%03d.%03d", split /[,.]/} %ips;
			last SWITCH;
		}
		if ($sort eq 'HNup') {
			$sortarrowhn = '&nbsp;&#9650;<!img src="/images/up.gif" alt="sort"/>';
			$hnsort = 'HNdown';
			@sorted_ip = map { $_->[1] } sort { lc($a->[0]) cmp lc($b->[0]) } map { [ $traffic{$_}{'hostname'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'HNdown') {
			$sortarrowhn = '&nbsp;&#9660;<!img src="/images/down.gif" alt="sort"/>';
			$hnsort = 'HNup';
			@sorted_ip = map { $_->[1] } sort { lc($b->[0]) cmp lc($a->[0]) } map { [ $traffic{$_}{'hostname'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'OUup') {
			$sortarrowou = '&nbsp;&#9650;<!img src="/images/up.gif" alt="sort"/>';
			$ousort = 'OUdown';
			@sorted_ip = map { $_->[1] } sort { $a->[0] <=> $b->[0] } map { [ $traffic{$_}{'alloutput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'OUdown') {
			$sortarrowou = '&nbsp;&#9660;<!img src="/images/down.gif" alt="sort"/>';
			$ousort = 'OUup';
			@sorted_ip = map { $_->[1] } sort { $b->[0] <=> $a->[0] } map { [ $traffic{$_}{'alloutput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'OUupM') {
			$sortarrowouM = '&nbsp;&#9650;<!img src="/images/up.gif" alt="sort"/>';
			$ousortM = 'OUdownM';
			@sorted_ip = map { $_->[1] } sort { $a->[0] <=> $b->[0] } map { [ $traffic{$_}{'monthoutput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'OUdownM') {
			$sortarrowouM = '&nbsp;&#9660;<!img src="/images/down.gif" alt="sort"/>';
			$ousortM = 'OUupM';
			@sorted_ip = map { $_->[1] } sort { $b->[0] <=> $a->[0] } map { [ $traffic{$_}{'monthoutput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'OUupW') {
			$sortarrowouW = '&nbsp;&#9650;<!img src="/images/up.gif" alt="sort"/>';
			$ousortW = 'OUdownW';
			@sorted_ip = map { $_->[1] } sort { $a->[0] <=> $b->[0] } map { [ $traffic{$_}{'weekoutput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'OUdownW') {
			$sortarrowouW = '&nbsp;&#9660;<!img src="/images/down.gif" alt="sort"/>';
			$ousortW = 'OUupW';
			@sorted_ip = map { $_->[1] } sort { $b->[0] <=> $a->[0] } map { [ $traffic{$_}{'weekoutput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'OUupD') {
			$sortarrowouD = '&nbsp;&#9650;<!img src="/images/up.gif" alt="sort"/>';
			$ousortD = 'OUdownD';
			@sorted_ip = map { $_->[1] } sort { $a->[0] <=> $b->[0] } map { [ $traffic{$_}{'dayoutput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'OUdownD') {
			$sortarrowouD = '&nbsp;&#9660;<!img src="/images/down.gif" alt="sort"/>';
			$ousortD = 'OUupD';
			@sorted_ip = map { $_->[1] } sort { $b->[0] <=> $a->[0] } map { [ $traffic{$_}{'dayoutput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'INup') {
			$sortarrowin = '&nbsp;&#9650;<!img src="/images/up.gif" alt="sort"/>';
			$insort = 'INdown';
			@sorted_ip = map { $_->[1] } sort { $a->[0] <=> $b->[0] } map { [ $traffic{$_}{'allinput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'INdown') {
			$sortarrowin = '&nbsp;&#9660;<!img src="/images/down.gif" alt="sort"/>';
			$insort = 'INup';
			@sorted_ip = map { $_->[1] } sort { $b->[0] <=> $a->[0] } map { [ $traffic{$_}{'allinput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'INupM') {
			$sortarrowinM = '&nbsp;&#9650;<!img src="/images/up.gif" alt="sort"/>';
			$insortM = 'INdownM';
			@sorted_ip = map { $_->[1] } sort { $a->[0] <=> $b->[0] } map { [ $traffic{$_}{'monthinput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'INdownM') {
			$sortarrowinM = '&nbsp;&#9660;<!img src="/images/down.gif" alt="sort"/>';
			$insortM = 'INupM';
			@sorted_ip = map { $_->[1] } sort { $b->[0] <=> $a->[0] } map { [ $traffic{$_}{'monthinput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'INupW') {
			$sortarrowinW = '&nbsp;&#9650;<!img src="/images/up.gif" alt="sort"/>';
			$insortW = 'INdownW';
			@sorted_ip = map { $_->[1] } sort { $a->[0] <=> $b->[0] } map { [ $traffic{$_}{'weekinput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'INdownW') {
			$sortarrowinW = '&nbsp;&#9660;<!img src="/images/down.gif" alt="sort"/>';
			$insortW = 'INupW';
			@sorted_ip = map { $_->[1] } sort { $b->[0] <=> $a->[0] } map { [ $traffic{$_}{'weekinput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'INupD') {
			$sortarrowinD = '&nbsp;&#9650;<!img src="/images/up.gif" alt="sort"/>';
			$insortD = 'INdownD';
			@sorted_ip = map { $_->[1] } sort { $a->[0] <=> $b->[0] } map { [ $traffic{$_}{'dayinput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
		if ($sort eq 'INdownD') {
			$sortarrowinD = '&nbsp;&#9660;<!img src="/images/down.gif" alt="sort"/>';
			$insortD = 'INupD';
			@sorted_ip = map { $_->[1] } sort { $b->[0] <=> $a->[0] } map { [ $traffic{$_}{'dayinput'}, $_ ] } keys %traffic;
			last SWITCH;
		}
	}


#	&Header::openbox('100%', 'left', "$Lang::tr{'IPTraffic_clientlist'}:");
	&Header::openbox('100%', 'left', 'IPTraffic Clientlist:');

	print" 
<table width='100%'>
	<tr bgcolor='#C0C0C0' style='heigt: 20px'>
		<td rowspan='2' width='30em' align='center'><b>Nr.</b></td>
		<td rowspan='2' align='center'><b>$Lang::tr{'interface'}</b></td>
		<td rowspan='2' width='110em' align='center'><b><a href='$ENV{'SCRIPT_NAME'}?SORT=$ipsort'>$Lang::tr{'ip address'} $sortarrowip</a></b></td>
		<td rowspan='2' width='110em' align='center'><b><a href='$ENV{'SCRIPT_NAME'}?SORT=$hnsort'>$Lang::tr{'hostname'} $sortarrowhn</a></b></td>
		<td colspan='4' align='center'><b>Gesendet$Lang::tr{'IPTraffic_send'}</b></td>
		<td colspan='4' align='center'><b>Laden$Lang::tr{'IPTraffic_load'}</b></td>
		<td colspan='3' align='center'><b>$Lang::tr{'action'}</b></td>
	</tr>
	<tr bgcolor='#C0C0C0'>
		<td align='center' style='width: 6em'><a href='$ENV{'SCRIPT_NAME'}?SORT=$insort'>Gesamt $sortarrowin</a></td>
		<td align='center' style='width: 6em'><a href='$ENV{'SCRIPT_NAME'}?SORT=$insortM'>Monat $sortarrowinM</a></td>
		<td align='center' style='width: 6em'><a href='$ENV{'SCRIPT_NAME'}?SORT=$insortW'>Woche $sortarrowinW</a></td>
		<td align='center' style='width: 6em'><a href='$ENV{'SCRIPT_NAME'}?SORT=$insortD'>Heute $sortarrowinD</a></td>
		<td align='center' style='width: 6em'><a href='$ENV{'SCRIPT_NAME'}?SORT=$ousort'>Gesamt $sortarrowou</a></td>
		<td align='center' style='width: 6em'><a href='$ENV{'SCRIPT_NAME'}?SORT=$ousortM'>Monat $sortarrowouM</a></td>
		<td align='center' style='width: 6em'><a href='$ENV{'SCRIPT_NAME'}?SORT=$ousortW'>Woche $sortarrowouW</a></td>
		<td align='center' style='width: 6em'><a href='$ENV{'SCRIPT_NAME'}?SORT=$ousortD'>Heute $sortarrowouD</a></td>
		<td align='center'><img src='$imgstatic/graph.png' alt='Gaph'/><!--$Lang::tr{'IPTraffic_graphs'}--></td>
		<td align='center'><img src='$imgsys/delete.gif' alt='$Lang::tr{'remove'}'/></td>
	</tr>";
	
		foreach my $ip (@sorted_ip) {
			if ($ip eq '0.0.0.0' || $ip eq '' || trim($traffic{$ip}{'limit'}) eq 'DEL') {next}
	
			$sum_incoming_all += $traffic{$ip}{'allinput'};
			$sum_outgoing_all += $traffic{$ip}{'alloutput'};
			$sum_incoming_month += $traffic{$ip}{'monthinput'};
			$sum_outgoing_month += $traffic{$ip}{'monthoutput'};
			$sum_incoming_week += $traffic{$ip}{'weekinput'};
			$sum_outgoing_week += $traffic{$ip}{'weekoutput'};
			$sum_incoming_day += $traffic{$ip}{'dayinput'};
			$sum_outgoing_day += $traffic{$ip}{'dayoutput'};
	
			my $netColor = getNetworkColor($ip);
	
			print "
	<tr class='table".($count++ % 2?1:2)."colour'".(gethostbyaddr(inet_aton($ip), AF_INET)?' style="color: #009000; "':'').">
		<td align='center' style='color: black;'>".$count."</td>
		<td align='center'><img src='$imgstatic/$netColor.png' alt='$netColor' title='$netColor' /></td>
		<td align='center'>$ip</td>
		<td align='center'>$traffic{$ip}{'hostname'}</td>
		<td align='center'>".calcTraffic($traffic{$ip}{'allinput'})."</td>
		<td align='center'>".calcTraffic($traffic{$ip}{'monthinput'})."</td>
		<td align='center'>".calcTraffic($traffic{$ip}{'weekinput'})."</td>
		<td align='center'>".calcTraffic($traffic{$ip}{'dayinput'})."</td>
		<td align='center'>".calcTraffic($traffic{$ip}{'alloutput'})."</td>
		<td align='center'>".calcTraffic($traffic{$ip}{'monthoutput'})."</td>
		<td align='center'>".calcTraffic($traffic{$ip}{'weekoutput'})."</td>
		<td align='center'>".calcTraffic($traffic{$ip}{'dayoutput'})."</td>
		<td align='center' width='5%'>
			<form method='post' name='graph".$idarp."' action='$ENV{'SCRIPT_NAME'}'>
				<input type='hidden' name='ACTION' value='GRAPH' />
				<input type='hidden' name='PARAM' value='$ip' />
				<input type='image' name='$traffic{$ip}{'hostname'}' src='$imgstatic/graph.png' alt='$Lang::tr{'IPTraffic_graphs'}' title='$Lang::tr{'IPTraffic_graphs'}' />
			</form>
		</td>
		<td align='center' width='5%'>
			<form method='post' name='delete".$idarp++."' action='$ENV{'SCRIPT_NAME'}'>
				<input type='hidden' name='ACTION' value='del' />
				<input type='hidden' name='PARAM' value='$ip' />
				<input type='image' name='$traffic{$ip}{'hostname'}' src='$imgsys/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
			</form>
		</td>
	</tr>
		";
		}
		print "
	<tr bgcolor='#C0C0C0'>
		<td align='right' colspan='4'>Gesamt</td>
		<td align='center'>".calcTraffic($sum_incoming_all)."</td>
		<td align='center'>".calcTraffic($sum_incoming_month)."</td>
		<td align='center'>".calcTraffic($sum_incoming_week)."</td>
		<td align='center'>".calcTraffic($sum_incoming_day)."</td>
		<td align='center'>".calcTraffic($sum_outgoing_all)."</td>
		<td align='center'>".calcTraffic($sum_outgoing_month)."</td>
		<td align='center'>".calcTraffic($sum_outgoing_week)."</td>
		<td align='center'>".calcTraffic($sum_outgoing_day)."</td>
		<td align='center' colspan='3'>&nbsp;</td>
	</tr>
</table>";
	
	&Header::closebox();
}

## arp table entries
sub disp_arp {
	my $output = `/sbin/ip neigh list`;
	my @clientlist = getIPfromTable();
#	my $buttonname = $Lang::tr{'IPTraffic_add'};
	my $buttonname = 'Client hinzuf&uuml;gen';
	my $count = 0;

	foreach my $line (split(/\n/, $output)){
		if ($line =~ m/^(.*) dev ([^ ]+) lladdr ([0-9a-f:]*) (.*)$/ || $line =~ m/^(.*) dev ([^ ]+)  (.*)$/) {
			my $hostname = gethostbyaddr(inet_aton($1), AF_INET);
			$arpcache{$1} = $2.",".( $hostname ? $hostname : '' )."\n";
		}
	}

	&Header::openbox('100%', 'left', "$Lang::tr{'arp table entries'}:");
	print"
<style>	.shownone { display: none; } </style>

<span style=\"float: left;\">$buttonname</span>
<span style=\"float: right;\"><button id='shownone'>Arp-Tabelle anzeigen</button></span><br/>
<p>
<table width='100%' class='shownone' style='display: none;'>
<tr style='background: #C0C0C0;'>
	<td width='15%' align='center' height='20'><b>$Lang::tr{'interface'}</b></td>
	<td width='15%' align='center' height='20'><b>$Lang::tr{'ip address'}</b></td>
	<td align='center' height='20'><b>$Lang::tr{'hostname'}</b></td>
	<td width='5%' align='center' height='20'><b>$Lang::tr{'action'}</b></td>
</tr>
";
	foreach my $key (sort keys %arpcache) {
		chomp ($key);
		@line = split (/\,/, $arpcache{$key});
		my $netname = (split(/-/,$line[0]))[0];
		chop $netname;
		chomp $line[1];
		print"
	<tr class='table".($count++ % 2?1:2)."colour' height='20'>
		<td align='center'><img src='$imgstatic/$netname.png' alt='$line[0]' title='$line[0]' /></td>
		<td align='center'>$key</td>
		<td align='center'>$line[1]</td>
		<td align='center'>";
		if (grep /^$key$/, @clientlist){
			print "
			<img src='$imgstatic/addfaint.gif' alt='$Lang::tr{'IPTraffic_no_add'}' title='$Lang::tr{'IPTraffic_no_add'}' />";
		}
		else {
			print "
			<form method='post' name='addfromlist".($idarp++)."' action='$ENV{'SCRIPT_NAME'}' enctype='multipart/form-data'>
			<input type='hidden' name='ACTION' value='add' />
			<input type='hidden' name='PARAM' value='$key' />
			<input type='hidden' name='CLIENTNAME' value='$line[1]' />
			<input type='image' name='$netname' src='$imgstatic/add$netname.gif' alt='$buttonname' title='$buttonname' />
			</form>";
		}
		print "
		</td>
	</tr>";
	}

	print"
</table>
</p>
<script>
var shownone = false;
document.querySelector(\"#shownone\").onclick = function () {
	if (shownone === false ) {
		document.querySelectorAll(\".shownone\")[0].style=\"display: block\";
		shownone = true;
		this.innerHTML = \"Arp-Tabelle ausblenden\";
	} else {
		document.querySelectorAll(\".shownone\")[0].style=\"display: none\";
		shownone = false;
		this.innerHTML = \"Arp-Tabelle anzeigen\";
	}
}
</script>
<br/><br/>";

	&Header::closebox();
}

sub calcTraffic {
	my $value = shift;
	my @unit = ('', 'K', 'M', 'G', 'T', 'P');
	my $i = 0;

	while ($value > 1000){
		$value = sprintf ( "%.1f", $value/1024);
		$i++;
	}
	return ($value < 0 ? "0" : $value+0 )."&nbsp;$unit[$i]B";
}

sub setClientAction {
	my $client = shift;
	my $action = shift;
	my $host = shift;
	my @status;

	print "SetClientAction: $action <br>";
	my $sql = '';
	if ($action eq 'ADD'){
		$sql = "INSERT INTO '".$IPTrafficTable."' (`client`, `hostname`, `date`) VALUES ( '".$client."', '".$host."', '".getToday()."');";
	}

	if ($action eq 'DEL'){
		$sql = "UPDATE '".$IPTrafficTable."' SET `traflimit` = 'DEL' WHERE `client` = '".$client."';";
	}
	my $dbh = DBI->connect("dbi:SQLite:dbname=$iptrafficdb", "", "", {RaiseError => 1, AutoCommit=>1});
	my $Action= $dbh->prepare($sql);
	$Action->execute();
	$Action->finish();
}

## get network color
sub getNetworkColor {
	my $ipaddress = shift;
	my %devs_color = ('GREEN' => 'green', 'BLUE' => 'blue', 'ORANGE' => 'orange', 'RED' => 'red', 'GRAY' => 'gray');

	for my $color (keys %devs_color) {
		my $interface = $devs_color{$color};
		next if ( $netsettings{$color."_DEV"} eq 'red0' && $netsettings{"RED_TYPE"} eq 'PPPOE');

		if ( &General::IpInSubnet($ipaddress, $netsettings{$color."_ADDRESS"}, $netsettings{$color."_NETMASK"}) ) {
			return $interface;
		}
	}
	return 'red';
}

sub getIPfromTable {
	my @clients = '';
	my ($client, $traflimit);
	my $sql;
	my $dbh = DBI->connect("dbi:SQLite:dbname=/var/log/iptraffic/iptraffic.db", "", "", {RaiseError => 1});
	$sql = "SELECT DISTINCT `client`, `traflimit` FROM `".$IPTrafficTable."` WHERE `date` = '".getToday()."';";
	my $Statement = $dbh->prepare($sql);
	$Statement->execute;
	$Statement->bind_columns(\$client, \$traflimit);
	while($Statement->fetch()){
		#if (trim($traflimit) eq 'DEL') { next };
		if($client > 0) {push(@clients, "$client");}
	}
	$Statement->finish();
	$dbh->disconnect() or warn $dbh->errstr;
	return @clients;
}

sub getAllTrafficFromTable {
	my %traffic;
	my @iplist = getIPfromTable();
	my ($client, $hostname, $date, $input, $output, $dayinput, $dayoutput, $weekinput, $weekoutput, $monthinput, $monthoutput, $traflimit, $port);

	my $dbh = DBI->connect("dbi:SQLite:dbname=/var/log/iptraffic/iptraffic.db", "", "", {RaiseError => 1});
	my $sql = '';
	my $Statement = $dbh->prepare($sql);
	foreach $client ( @iplist) {
		$client = trim($client);
		$sql = "SELECT `hostname`, sum(`input`), sum(`output`), ";
		$sql.= "(SELECT sum(input) from '".$IPTrafficTable."' WHERE `client` = '".$client."' AND `date` = '".getToday()."') as `dayinput`, ";
		$sql.= "(SELECT sum(output) from '".$IPTrafficTable."' WHERE `client` = '".$client."' AND `date` = '".getToday()."') as `dayoutput`, ";
		$sql.= "(SELECT sum(input) from '".$IPTrafficTable."' WHERE `client` = '".$client."' AND `date` BETWEEN '".getDayBeforAWeek()."' AND '".getToday()."') as `weekinput`, ";
		$sql.= "(SELECT sum(output) from '".$IPTrafficTable."' WHERE `client` = '".$client."' AND `date` BETWEEN '".getDayBeforAWeek()."' AND '".getToday()."') as `weekoutput`, ";
		$sql.= "(SELECT sum(input) from '".$IPTrafficTable."' WHERE `client` = '".$client."' AND `date` BETWEEN '".getDayBeforAMonth()."' AND '".getToday()."') as `monthinput`, ";
		$sql.= "(SELECT sum(output) from '".$IPTrafficTable."' WHERE `client` = '".$client."' AND `date` BETWEEN '".getDayBeforAMonth()."' AND '".getToday()."') as `monthoutput`, ";
		$sql.= "`traflimit`, `port` from '".$IPTrafficTable."' WHERE `client` = '".$client."';";
		$Statement = $dbh->prepare($sql);
		$Statement->execute;
		$Statement->bind_columns(\$hostname, \$input, \$output, \$dayinput, \$dayoutput, \$weekinput, \$weekoutput, \$monthinput, \$monthoutput, \$traflimit, \$port);
		while($Statement->fetch()) {
			$traffic{$client} = {'hostname' => $hostname, 'allinput' => $input, 'alloutput' => $output, 'dayinput' => $dayinput, 'dayoutput' => $dayoutput, 'weekinput' => $weekinput, 'weekoutput' => $weekoutput, 'monthinput' => $monthinput, 'monthoutput' => $monthoutput, 'limit' => $traflimit, 'port' => $port};
		}
	}
	$Statement->finish();
	$dbh->disconnect() or warn $dbh->errstr;

	return %traffic;
}

sub getToday {
	my ($Sekunden, $Minuten, $Stunden, $Monatstag, $Monat, $Jahr, $Wochentag, $Jahrestag, $Sommerzeit) = localtime(time);
	return sprintf "%04d%02d%02d" , $Jahr+1900 , $Monat+1 , $Monatstag ;
}

sub getYesterday {
	my ($Sekunden, $Minuten, $Stunden, $Monatstag, $Monat, $Jahr, $Wochentag, $Jahrestag, $Sommerzeit) = localtime(time-86400);
	return sprintf "%04d%02d%02d" , $Jahr+1900 , $Monat+1 , $Monatstag ;
}

sub getDayBeforAWeek {
	my ($Sekunden, $Minuten, $Stunden, $Monatstag, $Monat, $Jahr, $Wochentag, $Jahrestag, $Sommerzeit) = localtime(time-604800);
	return sprintf "%04d%02d%02d" , $Jahr+1900 , $Monat+1 , $Monatstag ;
}

sub getDayBeforAMonth {
	my ($Sekunden, $Minuten, $Stunden, $Monatstag, $Monat, $Jahr, $Wochentag, $Jahrestag, $Sommerzeit) = localtime(time-2592000);
	return sprintf "%04d%02d%02d" , $Jahr+1900 , $Monat+1 , $Monatstag ;
}

sub trim() {
	my $str = shift;
	$str =~ s/^\s+|\s+$//g;
	return $str;
}
############################################################################################################################

sub hrline { 

print"<table width='100%'><tr><td colspan='2' height='35'><hr></td></tr></table>";

}

