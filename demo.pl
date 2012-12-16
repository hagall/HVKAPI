	use HVKAPI;
	use Data::Dumper;
	use utf8;
	use open qw/:std :utf8/;

							# First of all, we create an object. We
							# will set captcha-callback, but leave
							# an application id and useragent to be
							# set to default values
	my $vk = new HVKAPI(\&captchaCallback);


	#----------------LOGIN-EXAMPLE------------------------------------	
							# Login attempt. Die if error occured.
	my %res = $vk->login('login', 'pass', 'phone');
	die("Error #$res{errcode}: $res{errdesc}") if ($res{errcode});
	print "Login successful!\n";

							# The request itself
	my $resp = $vk->request('getProfiles', {'uids'=>'1', "test" => "2"});

	print Dumper($resp);				# Shows the response in a structured view.
	print $resp->{response}->[0]->{first_name};
	#----------------------------------------------------------------


	#-----------------REGISTRATION-EXAMPLE----------------------------
							# Registration attempt
	print "Trying to register...\n";

	my %res = $vk->register('+79214104488', 'Vasiliy', 'Pupkin');
	die("Error #$res{errcode}: $res{errdesc}") if ($res{errcode});

	print "Sms sent.\nEnter smscode:\n";
	my $smscode = <>;
	%res = $vk->confirm_register("password", $smscode);
	die("Error #$res{errcode}: $res{errdesc}") if ($res{errcode});
	#-----------------------------------------------------------------

sub captchaCallback
{
	my $cvars = shift;
	my $url = $cvars->{captcha_url};
	my $answer;

	print "\nHouston, we have a captcha!\n$url\nAnswer: \n";
	$answer = <>;
	chomp $answer;

	return $answer;
}

