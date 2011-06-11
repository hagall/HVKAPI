<?php	
	require 'HVKAPI.php';	
	
							# First of all, we create an object. We
							# will set captcha-callback, but leave
							# an application id and useragent to be
							# set to default values	
	$VK = new hvkapi('myCallback');
	
							# Login attempt. Die if error occured.	
	$res = $VK->login('email', 'pass');
	if ($res['errcode']) die("Error code: {$res['errcode']}. {$res['errdesc']}");
	
							# The request itself	
	$resp = $VK->request('getProfiles', array('uids'=>'1,23363'));
	print_r($resp);
	
function myCallback($params)
{
	$difficulty = $params['difficult'];
	$sid = $params['captcha_sid'];
	$difficulty = !$difficulty;
	print "http://vkontakte.ru/captcha.php?sid=$sid&s=$difficulty\n";
	return trim(fgets(STDIN));
}
	
?>	

