	use HVKAPI;
	use Data::Dumper;
	
	my $vk = new HVKAPI;
	my %res = $vk->login('email', 'pass');
	die("Error #$res{errcode}: $res{errdesc}") if ($res{errcode});
	my $resp = $vk->request('getProfiles', {'uids'=>'28818464,23363'});
	
	print Dumper($resp);				# Shows the response in a structured view.
	print $resp->{response}->[0]->{first_name};  

