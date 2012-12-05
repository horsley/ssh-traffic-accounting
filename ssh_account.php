#!/usr/bin/php
<?php
/**
 *	 SSH Traffic Accounting script on Linux
 * 	 Base on http://newspaint.wordpress.com/2011/08/02/ssh-traffic-accounting-on-linux/ in perl
 * 	 I translate that script into PHP version
 * 	 @author: horsley
 * 	 @link: http://a-li.me
 * 
 * 	 
 * 
 * 	 Notice:
 * 	 1. Remember to start iptables service
 * 	 2. Remember to chmod+x
 * 	 3. How to start running this script?
 * 		setsid /usr/bin/tail -n 0 -F /var/log/auth.log |/root/ssh_account.php 2>/dev/null &
 * 		suppose this script save as /root/ssh_account.php
 * 		notice that the auth log file was /var/log/secre in CentOS and other RedHat-based distros
 * 	 4. About SSH Tunnelling traffic
 * 		It's obviously that this script can only count the traffic between SSH server and clients,
 * 		If the user login via ssh and setup tunnel for other programs, those traffic between SSH server and tunnel target will NOT be counted
 * 		but if the SSH server was only used for SSH Tunnelling, you can roughly double the bytes counted
 */


$iptables = '/sbin/iptables';

define(LOG_FILE, dirname(__FILE__) . '/SSH_Traffic_Logs');


###############################################################
$pidlist = array();

function process_log_line($line) {
	global $pidlist;

	$pid = '';
	$msg = '';

	if(preg_match('/sshd\[(\d+)\]:\s+(.+)$/', $line, $param)) {
		$pid = $param[1];
		$msg = $param[2];
	} else {
		return;
	}

	$piduser = '';
	if(!empty($pidlist[$pid])) {
		$piduser = $pidlist[$pid]->user;
	}

	if(preg_match('/Accepted \S+ for (\S+(?:.+\S)?) from (\d+\.\d+\.\d+\.\d+) port (\d+)/', $msg, $param)) {
		$pidlist[$pid] = new stdClass();

		$pidlist[$pid]->user = $param[1];
		$pidlist[$pid]->ip = $param[2];
		$pidlist[$pid]->port = $param[3];

		$pidlist[$pid]->pid = $pid;

		add_entry($pidlist[$pid]);
	} elseif (!empty($pidlist[$pid]) && preg_match("/session closed for user \Q$piduser\E/", $msg, $param)) {

		del_entry($pidlist[$pid]);
	}
}

function add_entry($obj) {
	global $iptables;

	$user = $obj->user;
	$ip   = $obj->ip  ;
	$port = $obj->port;
	$pid  = $obj->pid ;
	
	$comment = "pid:$pid user:$user";

	$cmd = "$iptables -t filter -I useraccount -s $ip -p tcp --sport $port -m comment --comment \"$comment\"";
	exec($cmd);
	$cmd = "$iptables -t filter -I useraccount -d $ip -p tcp --dport $port -m comment --comment \"$comment\"";
	exec($cmd);

	save_logs("$user login from $ip port $port");
}

function del_entry($obj) {
	global $iptables, $pidlist;

	$user = $obj->user;
	$ip   = $obj->ip  ;
	$port = $obj->port;
	$pid  = $obj->pid ;
	
	$comment = "pid:$pid user:$user";

	read_traffic_bytes($pidlist[$pid]);

	$cmd = "$iptables -t filter -D useraccount -s $ip -p tcp --sport $port -m comment --comment \"$comment\"";
	exec($cmd);
	$cmd = "$iptables -t filter -D useraccount -d $ip -p tcp --dport $port -m comment --comment \"$comment\"";
	exec($cmd);

	unset($pidlist[$pid]);
}

function read_traffic_bytes ($obj) {
	$cmd = "iptables -L useraccount -v -n -x";
	exec($cmd, $output);

	$user = $obj->user;
	$ip   = $obj->ip  ;
	$port = $obj->port;
	$pid  = $obj->pid ;

	foreach ($output as $value) {
		if(preg_match("/\s*\d+\s+(\d+)\s+\s*tcp.*tcp\s+(d|s)pt:.*\/\*\s*pid:$pid\s+user:$user\s*\*\//", $value, $param)) {
			if ($param[2] == 'd') { //server -> client
				$send_bytes = $param[1];
			} else {
				$recv_bytes = $param[1];
			}
		}
	}

	save_logs("$user logout from $ip port $port, server send $send_bytes bytes and receive $recv_bytes bytes");
}

function save_logs($log) {
	$time = date("[Y/m/d H:i:s]");
	$log = $time . " " . $log . PHP_EOL;

	if (!$handle = fopen(LOG_FILE, 'a')) {
		return false;
	}
	if (fwrite($handle, $log) === FALSE) {
		return false;
    }
    fclose($handle);
    return true;
}

function setup_iptables() {
	global $iptables;

	#echo " - setting up iptables\n";

	$cmd = "$iptables -F useraccount";
	exec($cmd);
	$cmd = "$iptables -N useraccount";
	exec($cmd);
	$cmd = "$iptables -D INPUT -p tcp -j useraccount";
	exec($cmd);
	$cmd = "$iptables -I INPUT -p tcp -j useraccount";
	exec($cmd);
	$cmd = "$iptables -D OUTPUT -p tcp -j useraccount";
	exec($cmd);
	$cmd = "$iptables -I OUTPUT -p tcp -j useraccount";
	exec($cmd);
}

function main() {
	setup_iptables();

	while (1) {
		while ($line = trim(fgets(STDIN))) {
			process_log_line($line);
		}
	}
}

main();