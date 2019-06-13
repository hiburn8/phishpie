<?php

/**

Phishpie Dashboard - A dashboard for visualising phishing campaign data.
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

//config
define('USERNAME','admin');
define('PASSWORD','phishpie');

//do we have ourselves a stowaway captain?
if (!isset($_SERVER['PHP_AUTH_USER'])) {
    header('WWW-Authenticate: Basic realm="My Realm"');
    header('HTTP/1.0 401 Unauthorized');
    echo 'Unauthorized';
    exit;
} else {
    if (($_SERVER['PHP_AUTH_USER'] != USERNAME) || $_SERVER['PHP_AUTH_PW'] != PASSWORD){
      die;
    }
}
//do we have all our cargo captain?
if (function_exists('mb_substr') == 0){ 
  echo '<p style="color:white;background-color:black;">Console: php-mbstring is missing - pretty flags have been disabled</b></p>';
}



if (!empty($_POST['CAMPAIGN_SIZE']) && is_numeric($_POST['CAMPAIGN_SIZE'])){
  define("CAMPAIGN_SIZE", $_POST['CAMPAIGN_SIZE']);
}else{
  define("CAMPAIGN_SIZE",0);
}
$whitelistedAddresses = ['daniel@hiburn8.org','idanielreece@gmail.com','daniel.reece@owasp.org','danielreece@outlook.com'];
$whitelistedIPs = ['81.109.213.79']; //home
//$whitelistedIPs = array_merge($whitelistedIPs, ['66.249.93.34','66.249.93.37','66.249.93.38']); //GoogleImageProxy

function formatDateRange($d1, $d2) {
    if (date('Y-m-d',$d1) === date('Y-m-d',$d2)) {
        # Same day
        return date('dS. F',$d1);
    } elseif (date('Y-m',$d1) === date('Y-m',$d2)) {
        # Same calendar month
        return date('dS',$d1) . date(' – dS F Y',$d2);
    } elseif (date('Y',$d1) === date('Y',$d2)) {
        # Same calendar year
        return date('dS F',$d1) . date(' – dS F',$d2);
    } else {
        # General case (spans calendar years)
        return date('dS F Y',$d1) . date(' – dS F Y',$d2);
    }
}
function find_security($hitarray){
  $security = [];
  if(isset($hitarray['host'])){
    if (strpos($hitarray['host'],'messagelabs.net') !== FALSE){array_push($security, 'Symantec messagelabs web proxy');}
  }
  if (!empty($security)){return $security;}
  return 0;
}

function is_image_proxy($hitarray){
  if(isset($hitarray['host'])){
    if ((strpos($hitarray['ua'], 'GoogleImageProxy')!== FALSE) || strpos($hitarray['ua'], 'YahooMailProxy')!== FALSE){ return 1;}
  }
  return 0;
}

function is_virus_scanner($hitarray){
  if(isset($hitarray['ua'])){
    if (strpos($hitarray['ua'],'virustotalcloud') !== FALSE){return 1;}
  }
  return 0;
}

function get_browser_agent($ua)
{
    if (strpos($ua, 'Opera') || strpos($ua, 'OPR/')) return 'Opera';
    elseif (strpos($ua, 'GoogleImageProxy')) return 'GoogleImageProxy';
    elseif (strpos($ua, 'YahooMailProxy') !== FALSE) return 'YahooMailProxy';
    elseif (strpos($ua, 'virustotalcloud')) return 'VirusTotal Cloud';
    elseif (strpos($ua, 'HubSpot') !== FALSE) return 'HubSpot Crawler';
    elseif (strpos($ua, 'Slackbot-LinkExpanding') !== FALSE) return 'Slackbot-LinkExpanding';
    elseif (strpos($ua, 'Python-urllib') !== FALSE) return 'Python-urllib';
    elseif (strpos($ua, 'Java/') !== FALSE) return 'Java';
    elseif (strpos($ua, 'curl/') !== FALSE) return 'cURL';
    elseif (strpos($ua, 'PhantomJS/') !== FALSE) return 'PhantomJS';
    elseif (strpos($ua, 'CriOS')) return 'Chrome';
    elseif (strpos($ua, 'Outlook-iOS') !== FALSE) return 'Outlook-iOS';
    elseif (strpos($ua, 'Microsoft Outlook')) return 'Microsoft Outlook';
    elseif (strpos($ua, 'Edge')) return 'Edge';
    elseif (strpos($ua, 'HeadlessChrome')) return 'Chrome';
    elseif (strpos($ua, 'Chrome')) return 'Chrome';
    elseif (strpos($ua, 'Safari')) return 'Safari';
    elseif (strpos($ua, 'Firefox')) return 'Firefox';
    elseif (strpos($ua, 'rv:11.0')) return 'IE 11';
    elseif (strpos($ua, 'MSIE 9')) return 'IE 9';
    elseif (strpos($ua, 'MSIE 8')) return 'IE 8';
    elseif (strpos($ua, 'MSIE 7')) return 'IE 7';
    elseif (strpos($ua, 'MSIE 6')) return 'IE 6';
    elseif (strpos($ua, 'AppleWebKit')) return 'AppleWebKit';
    return 'Other';
}

function get_browser_OS($ua){
    if (strpos($ua, 'GoogleImageProxy')) return 'GoogleImageProxy';
    elseif (strpos($ua, 'YahooMailProxy') !== FALSE) return 'YahooMailProxy';
    elseif (strpos($ua, 'virustotalcloud')) return 'VirusTotal Cloud';
    elseif (strpos($ua, 'HubSpot') !== FALSE) return 'HubSpot Crawler';
    elseif (strpos($ua, 'Slackbot-LinkExpanding') !== FALSE) return 'Slackbot-LinkExpanding';
    elseif (strpos($ua, 'CrOS')) return 'ChromeOS';
    elseif (strpos($ua, 'Android')) return 'Android';
    if (preg_match('/(?:iPhone|iPad|iPod) OS (\d\d?_\d_?\d?)/', $ua, $matches)){ return 'iOS ' . str_replace('_','.',$matches[1]);;}
    elseif (strpos($ua, 'Outlook-iOS') !== FALSE) return 'iOS';
    elseif (strpos($ua, 'Windows NT 10')) return 'Windows 10';
    elseif (strpos($ua, 'Windows NT 6.3')) return 'Windows 8.1';
    elseif (strpos($ua, 'Windows NT 6.1')) return 'Windows 7';
    elseif (strpos($ua, 'Windows NT 6.0')) return 'Windows Vista';
    elseif (strpos($ua, 'Windows NT 5.1')) return 'Windows XP';
    elseif (strpos($ua, 'Windows NT 5.2')) return 'Windows Server 2003';
    elseif (strpos($ua, 'Mac OS X')) return 'OSX';
    elseif (strpos($ua, 'Linux x86_64')) return 'Linux';
    return 'Other';
}

function get_browser_device($ua){
    if (strpos($ua, 'GoogleImageProxy')) return 'GoogleImageProxy';
    elseif (strpos($ua, 'YahooMailProxy') !== FALSE) return 'YahooMailProxy';
    elseif (strpos($ua, 'virustotalcloud')) return 'VirusTotal Cloud';
    elseif (stripos($ua, 'iPhone')) return 'iPhone';
    elseif (stripos($ua, 'iPad')) return 'iPad';
    elseif (stripos($ua, 'iPod')) return 'iPod';
    elseif (strpos($ua, 'CrOS')) return 'Chromebook';
    elseif (strpos($ua, 'Samsung')) return 'Samsung';
    elseif (strpos($ua, 'Blackberry')) return 'Blackberry';
    elseif (strpos($ua, 'Android')) return 'Android';
    elseif (strpos($ua, 'Windows')) return 'PC';
    elseif (strpos($ua, 'Macintosh')) return 'Macintosh';
    elseif (strpos($ua, 'Linux x86_64')) return 'Linux';
    return 'Other';
}

function reverse_password_policy($password){
  $policy = '';
  $policy .= strlen($password).' Char';
  if(preg_match('/[a-z]/', $password)) {$policy .= ', LC';}
  if(preg_match('/[A-Z]/', $password)) {$policy .= ', UC';}
  if(preg_match('/[0-9]/', $password)) {$policy .= ', D';}
  if(preg_match('/[^\w]/', $password)) {$policy .= ', S';}
  return $policy; 
}

function is_strong_password($password){
  $uppercase = preg_match('/[A-Z]/', $password);
  $lowercase = preg_match('/[a-z]/', $password);
  $number    = preg_match('/[0-9]/', $password);
  $specialChars = preg_match('/[^\w]/', $password);

  if(!$uppercase || !$lowercase || !$number || !$specialChars || strlen($password) < 8) {
    return 0;
  }
    return 1;
}

function get_browser_combined($ua){
  $a = get_browser_agent($ua);
  $b = get_browser_OS($ua);

  if ($a == "GoogleImageProxy") return 'GoogleImageProxy';
  elseif ($a == $b) return $a;
  return $a . ' on ' . $b;
}

$ccs = array('AF'=>'Afghanistan','AX'=>'Åland Islands','AL'=>'Albania','DZ'=>'Algeria','AS'=>'American Samoa','AD'=>'Andorra','AO'=>'Angola','AI'=>'Anguilla','AQ'=>'Antarctica','AG'=>'Antigua and Barbuda','AR'=>'Argentina','AM'=>'Armenia','AW'=>'Aruba','AU'=>'Australia','AT'=>'Austria','AZ'=>'Azerbaijan','BH'=>'Bahrain','BS'=>'Bahamas','BD'=>'Bangladesh','BB'=>'Barbados','BY'=>'Belarus','BE'=>'Belgium','BZ'=>'Belize','BJ'=>'Benin','BM'=>'Bermuda','BT'=>'Bhutan','BO'=>'Bolivia','BQ'=>'Bonaire','BA'=>'Bosnia and Herzegovina','BW'=>'Botswana','BV'=>'Bouvet Island','BR'=>'Brazil','IO'=>'British Indian Ocean Territory','BN'=>'Brunei Darussalam','BG'=>'Bulgaria','BF'=>'Burkina Faso','BI'=>'Burundi','KH'=>'Cambodia','CM'=>'Cameroon','CA'=>'Canada','CV'=>'Cape Verde','KY'=>'Cayman Islands','CF'=>'Central African Republic','TD'=>'Chad','CL'=>'Chile','CN'=>'China','CX'=>'Christmas Island','CC'=>'Cocos (Keeling) Islands','CO'=>'Colombia','KM'=>'Comoros','CG'=>'Congo','CD'=>'Congo','CK'=>'Cook Islands','CR'=>'Costa Rica','CI'=>'Côte d\'Ivoire','HR'=>'Croatia','CU'=>'Cuba','CW'=>'Curaçao','CY'=>'Cyprus','CZ'=>'Czech Republic','DK'=>'Denmark','DJ'=>'Djibouti','DM'=>'Dominica','DO'=>'Dominican Republic','EC'=>'Ecuador','EG'=>'Egypt','SV'=>'El Salvador','GQ'=>'Equatorial Guinea','ER'=>'Eritrea','EE'=>'Estonia','ET'=>'Ethiopia','FK'=>'Falkland Islands (Malvinas)','FO'=>'Faroe Islands','FJ'=>'Fiji','FI'=>'Finland','FR'=>'France','GF'=>'French Guiana','PF'=>'French Polynesia','TF'=>'French Southern Territories','GA'=>'Gabon','GM'=>'Gambia','GE'=>'Georgia','DE'=>'Germany','GH'=>'Ghana','GI'=>'Gibraltar','GR'=>'Greece','GL'=>'Greenland','GD'=>'Grenada','GP'=>'Guadeloupe','GU'=>'Guam','GT'=>'Guatemala','GG'=>'Guernsey','GN'=>'Guinea','GW'=>'Guinea-Bissau','GY'=>'Guyana','HT'=>'Haiti','HM'=>'Heard Island and McDonald Islands','VA'=>'Holy See (Vatican City State)','HN'=>'Honduras','HK'=>'Hong Kong','HU'=>'Hungary','IS'=>'Iceland','IN'=>'India','ID'=>'Indonesia','IR'=>'Iran','IQ'=>'Iraq','IE'=>'Ireland','IM'=>'Isle of Man','IL'=>'Israel','IT'=>'Italy','JM'=>'Jamaica','JP'=>'Japan','JE'=>'Jersey','JO'=>'Jordan','KZ'=>'Kazakhstan','KE'=>'Kenya','KI'=>'Kiribati','KP'=>'Korea','KR'=>'Korea','KW'=>'Kuwait','KG'=>'Kyrgyzstan','LA'=>'Lao People\'s Democratic Republic','LV'=>'Latvia','LB'=>'Lebanon','LS'=>'Lesotho','LR'=>'Liberia','LY'=>'Libya','LI'=>'Liechtenstein','LT'=>'Lithuania','LU'=>'Luxembourg','MO'=>'Macao','MK'=>'Macedonia','MG'=>'Madagascar','MW'=>'Malawi','MY'=>'Malaysia','MV'=>'Maldives','ML'=>'Mali','MT'=>'Malta','MH'=>'Marshall Islands','MQ'=>'Martinique','MR'=>'Mauritania','MU'=>'Mauritius','YT'=>'Mayotte','MX'=>'Mexico','FM'=>'Micronesia','MD'=>'Moldova','MC'=>'Monaco','MN'=>'Mongolia','ME'=>'Montenegro','MS'=>'Montserrat','MA'=>'Morocco','MZ'=>'Mozambique','MM'=>'Myanmar','NA'=>'Namibia','NR'=>'Nauru','NP'=>'Nepal','NL'=>'Netherlands','NC'=>'New Caledonia','NZ'=>'New Zealand','NI'=>'Nicaragua','NE'=>'Niger','NG'=>'Nigeria','NU'=>'Niue','NF'=>'Norfolk Island','MP'=>'Northern Mariana Islands','NO'=>'Norway','OM'=>'Oman','PK'=>'Pakistan','PW'=>'Palau','PS'=>'Palestine','PA'=>'Panama','PG'=>'Papua New Guinea','PY'=>'Paraguay','PE'=>'Peru','PH'=>'Philippines','PN'=>'Pitcairn','PL'=>'Poland','PT'=>'Portugal','PR'=>'Puerto Rico','QA'=>'Qatar','RE'=>'Réunion','RO'=>'Romania','RU'=>'Russian Federation','RW'=>'Rwanda','BL'=>'Saint Barthélemy','SH'=>'Saint Helena','KN'=>'Saint Kitts and Nevis','LC'=>'Saint Lucia','MF'=>'Saint Martin (French part)','PM'=>'Saint Pierre and Miquelon','VC'=>'Saint Vincent and the Grenadines','WS'=>'Samoa','SM'=>'San Marino','ST'=>'Sao Tome and Principe','SA'=>'Saudi Arabia','SN'=>'Senegal','RS'=>'Serbia','SC'=>'Seychelles','SL'=>'Sierra Leone','SG'=>'Singapore','SX'=>'Sint Maarten (Dutch part)','SK'=>'Slovakia','SI'=>'Slovenia','SB'=>'Solomon Islands','SO'=>'Somalia','ZA'=>'South Africa','GS'=>'South Georgia and the South Sandwich Islands','SS'=>'South Sudan','ES'=>'Spain','LK'=>'Sri Lanka','SD'=>'Sudan','SR'=>'Suriname','SJ'=>'Svalbard and Jan Mayen','SZ'=>'Swaziland','SE'=>'Sweden','CH'=>'Switzerland','SY'=>'Syrian Arab Republic','TW'=>'Taiwan','TJ'=>'Tajikistan','TZ'=>'Tanzania','TH'=>'Thailand','TL'=>'Timor-Leste','TG'=>'Togo','TK'=>'Tokelau','TO'=>'Tonga','TT'=>'Trinidad and Tobago','TN'=>'Tunisia','TR'=>'Turkey','TM'=>'Turkmenistan','TC'=>'Turks and Caicos Islands','TV'=>'Tuvalu','UG'=>'Uganda','UA'=>'Ukraine','AE'=>'United Arab Emirates','GB'=>'United Kingdom','US'=>'United States','UM'=>'United States Minor Outlying Islands','UY'=>'Uruguay','UZ'=>'Uzbekistan','VU'=>'Vanuatu','VE'=>'Venezuela','VN'=>'Viet Nam','VG'=>'Virgin Islands','VI'=>'Virgin Islands','WF'=>'Wallis and Futuna','EH'=>'Western Sahara','YE'=>'Yemen','ZM'=>'Zambia','ZW'=>'Zimbabwe');

function get_country_from_countrycode($ccs, $cc){
  if (!preg_match("/[a-z]{2}/i", $cc)) return 0; 
  $cc = strtoupper($cc);
  return (!empty($ccs[$cc]) ? $ccs[$cc] : 0);
}

function get_flag_from_countrycode($s){
  if (function_exists('mb_substr') == 0){ return '';}
  if (!preg_match("/[a-z]{2}/i", $s)) return 0; 
  $s = strtoupper($s);
  $a = str_split($s);
  $r = "";
  $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  $emojibet = '🇦🇧🇨🇩🇪🇫🇬🇭🇮🇯🇰🇱🇲🇳🇴🇵🇶🇷🇸🇹🇺🇻🇼🇽🇾🇿';

  foreach ($a as $c) {
    $pos = strpos($alphabet, $c);
    $r .= mb_substr($emojibet,$pos,1,'UTF-8');
  }
  return $r;
}

//in order of unpacking sequence
$virus_scanned = array();
$read_viaproxy = array();
$read = array();
$submitted = array();
$submittedemails = array();
$clicked = array();

$passwords = array();
$browsers = array();
$platforms = array();
$devices = array();

$empty_passwords = 0;
$strong_passwords = 0;
$weak_passwords = 0;
$password_policies = array();

$useragents = array();
$uuids = array();
$referers = array();
$IPs = array();
$countries = array();
$languages = array();

if (!empty($_FILES['uploaded_file']) && $_FILES['uploaded_file']['error'] != 4){
  if(file_exists($_FILES['uploaded_file']['tmp_name']) || is_uploaded_file($_FILES['uploaded_file']['tmp_name'])) {
    $handle = fopen($_FILES['uploaded_file']['tmp_name'], "r");
  }  
}
elseif(file_exists("lootfile.txt")){
  $handle = fopen("lootfile.txt", "r");
}

/**
else{
  touch('lootfile.txt');
  $handle = fopen("lootfile.txt", "r");
}
**/

if (isset($handle)) {

    $firstRow = true;
    while (($line = fgets($handle)) !== false) {

    	$hitarray = unserialize($line) or print('cant unserialize ' . $line);

      #find campaign duration.
      if($firstRow == true) {
        $starttime = $hitarray['time'];
        $firstRow = false;
      }else{
        #this is a disgusting hack - i'm sorry.
        $endtime = $hitarray['time'];
      }


      #skip if it was our IP
      if(isset($hitarray['ip'])){
        if (in_array($hitarray['ip'], $whitelistedIPs)){ continue; }
      }
      #skip if it was our email
    	if(isset($hitarray['pixel'])){
        if (in_array($hitarray['pixel'], $whitelistedAddresses)){ continue; }
    	}
      #skip if it was our email
      if(isset($hitarray['email'])){
        if (in_array($hitarray['email'], $whitelistedAddresses)){ continue; }
      }

      #unpack virus-scanning
      if(is_virus_scanner($hitarray)){
        array_push($virus_scanned,$hitarray['time']);
      }
      #unpack 'read-email' events
      elseif(isset($hitarray['pixel'])){
        if(isset($hitarray['ua'])) {
          if (is_image_proxy($hitarray)){
            array_push($read_viaproxy,$hitarray['pixel']);
          }
          else{
            array_push($read,$hitarray['pixel']);
          }
        }
      }
      #unpack 'submitted-data' events 
      elseif (isset($hitarray['username']) || 
      isset($hitarray['password']) ||
      isset($hitarray['sFirstName']) || 
      isset($hitarray['sLastName']) || 
      isset($hitarray['sEmailAddress']) || 
      isset($hitarray['sPasswordNew']) || 
      isset($hitarray['email'])){
        #record submit event
        array_push($submitted,$hitarray['time']);
        #log emails for follow-ups, training, and triage. NOTE: the order of precedence here and strtolower'ing wont be suitable for all engagements. 
        if (isset($hitarray['email'])){
          array_push($submittedemails,strtolower($hitarray['email']));
        }
        elseif (isset($hitarray['sEmailAddress'])){
          array_push($submittedemails,strtolower($hitarray['sEmailAddress']));
        }
        elseif (isset($hitarray['username'])){
          array_push($submittedemails,strtolower($hitarray['username']));
        }
        
      }
      else
      #unpack 'clicked' events 
      {
        array_push($clicked,$hitarray['time']);
      }
      
      #unpack everything else 
      #skip if it came from a proxy
      if (is_image_proxy($hitarray['ua'])){
        continue;
      }
      #passwords
      if(isset($hitarray['password'])){
        array_push($passwords,$hitarray['password']);
        
        #passwordstrength
        if ($hitarray['password'] === ""){
          $empty_passwords = $empty_passwords +1;
        }
        elseif (is_strong_password($hitarray['password'])){
          $strong_passwords = $strong_passwords +1;
        }
        else{
          $weak_passwords = $weak_passwords +1;
        }
        #passwordpolicyreverse
        if($hitarray['password'] != ""){
          array_push($password_policies,reverse_password_policy($hitarray['password']));
        }

      }
      #UAs
    	if(isset($hitarray['ua'])){
        //&& empty($hitarray['pixel'])
        array_push($browsers,get_browser_agent($hitarray['ua']));
        array_push($platforms,get_browser_OS($hitarray['ua']));
        array_push($devices,get_browser_device($hitarray['ua']));
        

      }
      #UUIDs
      if(isset($hitarray['uuid'])){
        array_push($uuids,$hitarray['uuid']);
      }
      #referers
  		if(isset($hitarray['referer'])){
        //array_push($referers,$hitarray['referer']);
      	array_push($referers,parse_url($hitarray['referer'], PHP_URL_HOST));
  		}
      #IPs
      if(isset($hitarray['host'])){
        array_push($IPs,$hitarray['host']);
      }else{
        array_push($IPs,$hitarray['ip']);
      }
      #country-codes
      if(isset($hitarray['cc'])){
        array_push($countries,$hitarray['cc']);
      }
      #language-codes
      if(isset($hitarray['lang'])){
        array_push($languages,$hitarray['lang']);
      }

  }
  fclose($handle);
}

#post-unpack sorting
$browsers_sorted = array_count_values($browsers);
  arsort($browsers_sorted);
$platforms_sorted = array_count_values($platforms);
  arsort($platforms_sorted);
$devices_sorted = array_count_values($devices);
  arsort($devices_sorted);
$useragents_sorted = array_count_values($useragents);

$submittedemail_sorteds = array_unique($submittedemails);

$referers_sorted = array_count_values(array_filter($referers));
  arsort($referers_sorted);
$IPs_sorted = array_count_values($IPs);
  arsort($IPs_sorted);
$countries_sorted = array_count_values($countries);
  arsort($countries_sorted);
$languages_sorted = array_count_values($languages);
  arsort($languages_sorted);
$passwords_sorted = array_count_values($passwords);
  arsort($passwords_sorted);
$password_policies_sorted = array_count_values($password_policies);
  arsort($password_policies_sorted);
?>

<!DOCTYPE html>
<html lang="en-US">
<head>
  <meta charset="UTF-8">
  <?php if (isset($_GET['autorefresh'])){ printf('<meta http-equiv="refresh" content="60">');} ?>
  <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
  <!--<script src="https://cdn.bootcss.com/countup.js/1.9.3/countUp.min.js"></script>-->
</head>
<!-- force horizontal printing -->
<style type="text/css" media="print">
@media print{@page {size: landscape}}
</style>

<body>
<h1>PhishPie - Results</h1>

<h2>Campaign size: <?php 
if (CAMPAIGN_SIZE === 0){
  echo 'unknown';
}else{
  echo CAMPAIGN_SIZE;
}
?></h2>

<h2>Campaign duration: <?php 
if (!empty($starttime) && !empty($endtime)){
  echo formatDateRange($starttime, $endtime);
}else{
  echo 'unknown';
}

?></h2>

<div align="left">
<button onclick="window.print()">Save page as PDF</button>
<hr>
</div>

<table><th>Engagement</th>
<tr>
	<td id="totalengagement"></td>
	<td id="eventengagement"></td>
</tr>
</table>
<hr>
<table><th>Users</th>
<tr>
	<td id="browsers"></td>
	<td id="devices"></td>
  <td id="useragents"></td>
</tr>
</table>
<hr>
<table><th>Geography</th>
<tr>
  <td id="languages"></td>
  <td id="countries"></td>
</tr>
</table>
<hr>
<table><th>Infrastructure</th>
<tr>
  <td id="referers"></td>
  <td id="IPs"></td>
</tr>
</table>
<hr>
<table><th>Passwords</th>
<tr>
  <td id="passwordstrength"></td>
  <td id="passwordpolicy"></td>
  <td id="passwordreuse"></td>
</tr>
</table>

<hr>

<table><th>Triage</th>
<tr><td>Users submitted senstive data<br>
<textarea rows="20" cols="75">
<?php foreach($submittedemail_sorteds as $email ){ print($email . '
');}?>
</textarea>
</td>
</tr>
</table>

<hr>

<table><th><a href="" onclick="redteam.style.visibility = 'visible';return false">Red-Team</a></th>
<tr id="redteam" style="visibility: hidden;"><td>IPs<br>
<textarea rows="20" cols="20">
  <?php foreach($IPs_sorted as $key => $value){ print($key.',
  ');}?>
</textarea>
</td>
</tr>
</table>

<hr>
<table><th>Upload historic data</th>
<tr>
  <td>
    <form enctype="multipart/form-data" action="" method="POST">
    <p>Campaign settings file</p>
    <input type="file" name="uploaded_file2"></input><br />
  </td>
  <td>
    <p>Campaign results file</p>
    <input type="file" name="uploaded_file"></input><br />
  </td>
  <td>
    <p>Manual settings</p>
    Campaign size: <input type="text" name="CAMPAIGN_SIZE"><br>
    
    Reverse Resolve All IPs: <input type="checkbox" name="reverseResolve" value="1" <?php if (!empty($_POST['reverseResolve'])) print 'checked'?>><br>

    <input type="submit" value="Submit"></input>
    </form>
  </td>
</tr>
</table>
<hr>
<div align="right">
Copyright © <?php echo date("Y"); ?> - Daniel Reece 
</div>


<script type="text/javascript">
// Load google charts
google.charts.load('current', {'packages':['corechart']});
google.charts.setOnLoadCallback(drawChart);

// Draw the chart and set the chart values
function drawChart() {
  var data = google.visualization.arrayToDataTable([

  ['Task', 'Hours per Day'],
  ['Clicked link', <?php print(sizeof(array_unique($clicked)));?>],
  ['Didn\'t click link', <?php print(CAMPAIGN_SIZE - sizeof(array_unique($clicked)));?>],
])

  var data2 = google.visualization.arrayToDataTable([
  ['Task', 'Hours per Day'],
  ['Read email via proxy', <?php print(sizeof($read_viaproxy));?>],
  ['Read email', <?php print(sizeof($read));?>],
  ['Clicked link', <?php print(sizeof($clicked));?>],
  ['Submitted data', <?php print(sizeof($submitted));?>],
  ['Virus scan', <?php print(sizeof($virus_scanned));?>],
])

  var data4 = google.visualization.arrayToDataTable([
  ['Task', 'Hours per Day'],
  	<?php
  foreach($browsers_sorted as $key => $value){ print("['" . $key ."', " .$value. "],");}?>
])
    var data5 = google.visualization.arrayToDataTable([
  ['Task', 'Hours per Day'],
  	<?php
	foreach($platforms_sorted as $key => $value){ print("['" . $key ."', " .$value. "],");}?>
])
    var data6 = google.visualization.arrayToDataTable([
  ['Task', 'Hours per Day'],
    <?php
    foreach($devices_sorted as $key => $value){ print("['" . $key ."', " .$value. "],");}?>
    //combined UA results:
    //foreach($useragents_sorted as $key => $value){ print("['" . $key ."', " .$value. "],");}?>
])
    var data7 = google.visualization.arrayToDataTable([
  ['Task', 'Hours per Day'],
    <?php
    foreach($referers_sorted as $key => $value){ 
      print("['" . $key ."', " .$value. "],");
    }


    ?>
])
  var data8 = google.visualization.arrayToDataTable([
  ['Task', 'Hours per Day'],
  <?php
  foreach($languages_sorted as $key => $value){
    $flag = get_flag_from_countrycode(substr($key, -2));
    print("['" . $key . " " . $flag . "', ".$value."],");
  }
  ?>

])
    var data13 = google.visualization.arrayToDataTable([
  ['Task', 'Hours per Day'],
  <?php
  foreach($countries_sorted as $key => $value){ 
    print('[" '); 
    print(get_flag_from_countrycode($key)); 
    print(' ' .get_country_from_countrycode($key).'", ' .$value. '],');
  }
  ?>

])
  var data9 = google.visualization.arrayToDataTable([
  ['Task', 'Hours per Day'],
  <?php    foreach($passwords_sorted as $key => $value){ 
      if ($key != "" && $value > 1){
      //if ($key != ""){
        
        //print('["'.str_repeat("*", strlen(($key))).'", ' .$value. '],');
        print('["'.htmlspecialchars($key).'", ' .$value. '],');
      }
    }
?>
])
  var data10 = google.visualization.arrayToDataTable([
  ['Task', 'Hours per Day'],
  ['Strong passwords', <?php print($strong_passwords);?>],
  ['Weak passwords', <?php print($weak_passwords);?>],
])
  var data11 = google.visualization.arrayToDataTable([
  ['Task', 'Hours per Day'],
    <?php
      foreach($password_policies_sorted as $key => $value){ print("['" . $key ."', " .$value. "],");}?>
])
  var data12 = google.visualization.arrayToDataTable([
  ['Task', 'Hours per Day'],
    <?php
      
      if (!empty($_POST['reverseResolve'])){
        foreach($IPs_sorted as $key => $value){ print("['" . gethostbyaddr($key) ."', " .$value. "],");}
      }
      else{
        foreach($IPs_sorted as $key => $value){ print("['" . $key ."', " .$value. "],");}
      }
      
      ?>
])
;

  // Optional; add a title and set the width and height of the chart
  var options = {'title':'Click rate', 'width':450, 'height':300, colors: ['#dc3912','#3366cc'], sliceVisibilityThreshold:0};
  var options2 = {'title':'Events triggered', 'width':450, 'height':300, colors: ['#3366cc','#FFF426','#FF9926', '#dc3912', '#000000'], pieSliceText: 'value', sliceVisibilityThreshold:0};
  var options4 = {'title':'Top browsers', 'width':450, 'height':300, chartArea: {width:"100%"}, sliceVisibilityThreshold:0}; 
  var options5 = {'title':'Top OSs', 'width':450, 'height':300, chartArea: {width:"100%"}, sliceVisibilityThreshold:0}; 
  var options6 = {'title':'Top devices', 'width':450, 'height':300, chartArea: {width:"100%"}, sliceVisibilityThreshold:0}; 
  var options7 = {'title':'Referers', 'width':450, 'height':300, chartArea: {width:"100%"}, sliceVisibilityThreshold:0}; 
  var options8 = {'title':'Top languages', 'width':450, 'height':300, chartArea: {width:"100%"}, sliceVisibilityThreshold:0}; 
  var options9 = {'title':'Top password-reuse', 'width':450, 'height':300, chartArea: {width:"100%"}, sliceVisibilityThreshold:0.01}; 
  var options10 = {'title':'Password included upper,lower,digit, special, >=8 chars', 'width':450, 'height':300, chartArea: {width:"100%"}, sliceVisibilityThreshold:0}; 
  var options11 = {'title':'Password policy guess', 'width':450, 'height':300, chartArea: {width:"100%"}, sliceVisibilityThreshold:0}; 
  var options12 = {'title':'Interesting Hosts (>1%)', 'width':450, 'height':300, chartArea: {width:"100%"}, pieSliceText:'value',sliceVisibilityThreshold:0.01}; 
  var options13 = {'title':'Top countries', 'width':450, 'height':300, chartArea: {width:"100%"}, sliceVisibilityThreshold:0}; 


  // Display the chart inside the <div> element with id="piechart"
  var chart = new google.visualization.PieChart(document.getElementById('totalengagement'));
  var chart2 = new google.visualization.PieChart(document.getElementById('eventengagement'));
  var chart4 = new google.visualization.PieChart(document.getElementById('browsers'));
  var chart5 = new google.visualization.PieChart(document.getElementById('devices'));
  var chart6 = new google.visualization.PieChart(document.getElementById('useragents'));
  var chart7 = new google.visualization.PieChart(document.getElementById('referers'));
  var chart8 = new google.visualization.PieChart(document.getElementById('languages'));
  var chart9 = new google.visualization.PieChart(document.getElementById('passwordreuse'));
  var chart10 = new google.visualization.PieChart(document.getElementById('passwordstrength'));
  var chart11 = new google.visualization.PieChart(document.getElementById('passwordpolicy'));
  var chart12 = new google.visualization.PieChart(document.getElementById('IPs'));
  var chart13 = new google.visualization.PieChart(document.getElementById('countries'));


  chart.draw(data, options);
  chart2.draw(data2, options2);
  chart4.draw(data4, options4);
  chart5.draw(data5, options5);
  chart6.draw(data6, options6);
  chart7.draw(data7, options7);
  chart8.draw(data8, options8);
  chart9.draw(data9, options9);
  chart10.draw(data10, options10);
  chart11.draw(data11, options11);
  chart12.draw(data12, options12);
  chart13.draw(data13, options13);

}



</script>

</body>
</html>

