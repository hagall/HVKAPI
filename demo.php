<?php	
	require 'HVKAPI.php';	
	$VK = new hvkapi();
	$res = $VK->login('email', 'pass');
	if ($res['errcode']) die("Error code: {$res['errcode']}. {$res['errdesc']}");
	
	$resp = $VK->request('getProfiles', array('uids'=>'1,23363'));
	print_r($resp);
?>	

