<?php	
	require 'HVKAPI.php';	
	$VK = new vkapi();
	$res = $VK->login('email', 'pass');
	if ($res['errcode']) die("Error code: {$res['errcode']}. {$res['errdesc']}");
	
	$resp = $VK->request('getProfiles', array('uids'=>'28818464,23363'));
	print_r($resp);
?>	

