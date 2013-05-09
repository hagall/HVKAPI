package HVKAPI;

#    HVKAPI - class for vk.com API
#    Copyright (C) 2011-2012 hagall (asbrandr@jabber.ru)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; withprint even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#    Rev10, 121212

use warnings;
use strict;
use utf8;

use LWP::Simple;
use LWP::Protocol::https;
use HTTP::Cookies;
use HTTP::Date qw(str2time);
use JSON;
use IO::String;
use Encode qw(encode_utf8);
#use Net::INET6Glue::INET_is_INET6;
#use Net::SSLGlue::LWP;

no  warnings;


our $VERSION = '1.2';
our $defaultAppId = 2256065;							# ID дефолтного приложения
our $appSettings = 'friends,photos,audio,video,docs,notes,pages,wall,groups,messages';
our $defaultAgent = 'Mozilla/5.0 (X11; Linux x86_64; rv:9.0.1) Gecko/20100101 Firefox/9.0.1';
our $defaultApiUrl = 'http://api.vk.com/api.php'; 				# URL для API-запросов

our @ISA = qw(Exporter);

#-----------------------------------------------------------------------------------------
#										Конструктор класса.
#										Rev3, 110329
sub new 
{
	my ($class, %args) = @_;
	my $self  = {};

	$self->{captcha_callback} = $args{captchaCallback} ? $args{captchaCallback} : 
							     undef;
	$self->{useragent} = $args{userAgent} ? $args{userAgent} : $defaultAgent;
	$self->{app_id} = $args{appId} ? $args{appId} : $defaultAppId;
	$self->{app_settings} = $appSettings;
	$self->{silent} = 0;
	$self->{timeprint} = $args{timeprint} ? $args{timeprint} : 0;
	$self->{response_handler} = $args{responseHandler} ? $args{responseHandler} : 
							     \&_defaultResponseHandler;

	$self->{api_url} = $defaultApiUrl;
	return bless $self;
}

#-----------------------------------------------------------------------------------------
#										Дефолтный хендлер
#										Rev1, 130331
sub _defaultResponseHandler
{
	my ($response, $ua, $h) = @_;
	
	die $response->status_line unless ($response->is_success || $response->is_redirect);
}

#-----------------------------------------------------------------------------------------
#										Восстановление сессии
#										Rev3, 130325
sub restoreSession
{
	my $self = shift;
	my $dataref = shift;
	($self->{access_token}, $self->{mid}) = ($dataref->{access_token}, $dataref->{mid});
	
						# Теперь подгружаем куки	
	my $cookieJar = new HTTP::Cookies();
	
						# Код, идущий ниже - почти копипаста с 
						# функции load модуля HTTP::Cookies
						# В случае изменения того кода 
						# этот код тоже необходимо будет обновить			
	my @cookieLines = split /\n/, $dataref->{cookies};
    	for (@cookieLines) 
    	{
		next unless s/^Set-Cookie3:\s*//;
		chomp;
		my $cookie;
		for $cookie ($cookieJar->_split_header_words($_)) 
		{
	    		my($key,$val) = splice(@$cookie, 0, 2);
	    		my %hash;
	    		while (@$cookie) 
	    		{
				my $k = shift @$cookie;
				my $v = shift @$cookie;
				$hash{$k} = $v;
	    		}
			my $version   = delete $hash{version};
		    	my $path      = delete $hash{path};
		    	my $domain    = delete $hash{domain};
		    	my $port      = delete $hash{port};
		    	my $expires   = str2time(delete $hash{expires});

		    	my $path_spec = exists $hash{path_spec}; delete $hash{path_spec};
		    	my $secure    = exists $hash{secure};    delete $hash{secure};
		    	my $discard   = exists $hash{discard};   delete $hash{discard};

		    	my @array =	($version,$val,$port,
				 	$path_spec,$secure,$expires,$discard);
		    	push(@array, \%hash) if %hash;
		    	$cookieJar->set_cookie($version, $key, $val, $path, $domain,
		    				$port, $path_spec, $secure, $expires,
		    				$discard);
		}
	}
	
	$self->{browser} = new LWP::UserAgent(agent => $self->{useragent}, timeprint => $self->{timeprint}, keep_alive => 1);
	$self->{browser}->ssl_opts(timeprint => $self->{timeprint}, Timeprint => $self->{timeprint});
	$self->{browser}->cookie_jar($cookieJar);
	$self->{browser}->default_header("Accept" 		=> "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
	$self->{browser}->default_header("Accept-Language" 	=> "ru-ru,ru;q=0.8,en-us;q=0.5,en;q=0.3");
	$self->{browser}->default_header("Accept-Encoding" 	=> "gzip, deflate");
	$self->{browser}->default_header("Accept-Charset"	=> "utf-8;q=0.7,*;q=0.7");
	
	$self->{browser}->add_handler(response_done => $self->{response_handler});		
	return 0;
}


#-----------------------------------------------------------------------------------------
#										Получение параметров сессии
#										Rev3, 130325
sub getSessionVars
{
	my $self = shift;
	my $browser = $self->{browser};
	bless $browser, 'LWP::UserAgent';
	return { "access_token" => $self->{access_token}, 
		 "mid" 		=> $self->{mid},
		 "cookies" 	=> $browser->cookie_jar()->as_string() 
		};
	
}

#-----------------------------------------------------------------------------------------
#										Проверка валидности сессии
#										Rev1, 130325
sub checkSession
{
	my $self = shift;
	my $response = $self->request("users.get", {"uids" => "1"});
	return !(defined $response->{response});	
}

#-----------------------------------------------------------------------------------------
#										Логин в API без компонента
#										Rev8, 120720
sub login
{
	my $self = shift;

	my ($ulogin, $upass, $mphone) = @_;


	my ($appId, $app_settings) 			= ($self->{app_id}, $self->{app_settings});
	my $captchaCallback 				= $self->{captcha_callback};

	($self->{mid}, $self->{access_token})		= (0, 0);

	my $browser 					= LWP::UserAgent->new(timeprint => $self->{timeprint}, keep_alive => 1,
										agent => $self->{useragent});
	$browser->ssl_opts(timeprint => $self->{timeprint}, Timeprint => $self->{timeprint});
	$browser->cookie_jar(new HTTP::Cookies());
	$browser->default_header("Accept" 		=> "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
	$browser->default_header("Accept-Language" 	=> "ru-ru,ru;q=0.8,en-us;q=0.5,en;q=0.3");
	$browser->default_header("Accept-Encoding" 	=> "gzip, deflate");
	$browser->default_header("Accept-Charset"	=> "utf-8;q=0.7,*;q=0.7");
	
	$browser->add_handler(response_done => $self->{response_handler});
						
										# Обычный логин ВК
	my $response					= $browser->get("http://m.vk.com/login?fast=1");
	my ($postlink)					= $response->decoded_content() =~ /method="post" action="(.*?)"/;	
	return ('errcode' => 106,
	        'errdesc' => 'Cannot parse ACTION link!') unless ($postlink);
	        
	$response					= $browser->post($postlink, {"email" => $ulogin, "pass" => $upass});

	while ($response->header("Location") =~ /sid=(\d+)/)
	{
										# Капча на логин. Такое бывает
		return (errcode => 109, 
			errdesc => "Houston, we have a captcha and no callback!") unless defined $self->{captcha_callback};

		my $sid 	= $1;
		my $dif 	= !($response->header("Location") =~ /dif=1/);
		my $callback 	= $self->{captcha_callback};
		my $cdata = { captcha_sid => $sid, difficult => $dif,
			      captcha_url => "http://vk.com/captcha.php?sid=$sid&s=$dif"
			    };
		my $post = {"mail" => $ulogin, "pass" => $upass, 'captcha_sid' => $sid, 'captcha_key' => &$callback($cdata) };

		$response = $browser->post($postlink, $post);		
	}

	if ($response->header("Location") =~ /m=1\&/)
	{
										# Либо логин-пароль неверный,
										# либо аккаунт не привязан к 
										# мобильному. Пытаемся залогиниться через
										# главную страницу (todo)
		return ('errcode' => 107,
	        	'errdesc' => 'Invalid login data!');	
	}
	
	unless ($response->header("Location"))
	{
		return ('errcode' => 108,
	        	'errdesc' => 'Invalid headers returned.') unless ($postlink);
	}
	
	$response					= $browser->get($response->header("Location"));
	
	if ($response->decoded_content() =~ /security_check/)
	{
		return ('errcode' => 103,
			'errdesc' => 'Holy shit! Security check!') unless ($mphone);

		
		my ($postlink)				= $response->decoded_content() =~ /method="post" action="(.*?)"/;
		
		return ('errcode' => 104,
			'errdesc' => 'Cannot parse security hash link!') unless ($postlink);

		$postlink = "http://m.vk.com".$postlink unless ($postlink =~ /^http/);

		$response 				= $browser->post($postlink, {"code" => $mphone});
		return ('errcode' => 105,
			'errdesc' => 'Cannot pass security check!') if ($response->decoded_content =~ /security_check/);

		return ('errcode' => 106,
			'errdesc' => 'Invalid headers!') unless (defined $response->header("Location"));
		$response				= $browser->get($response->header("Location"));
	}


							
										# Логин за API
	$response 					= $browser->get("http://oauth.vk.com/oauth/authorize?client_id=$appId".
									"&scope=$appSettings".
									"&display=wap&response_type=token");
	my ($access_token, $user_id);		
										# Т.к. мы уже залогинились за вконтакт
										# заново вводить логпасс не нужно
	unless ($response->previous() && $response->previous()->header("Location") =~ /access_token/)
	{
										# Логинимся в первый раз, нужно
										# выставить настройки
		my ($link) 				= $response->decoded_content() =~ /(login\.vk\.com.*?)"/;
		return ('errcode' => 101,
			'errdesc' => 'Cannot parse redirect link!') unless ($link);
			
		$response				= $browser->get("https://$link");
		if (defined $response->previous())
		{
			my $redirect = $response->previous()->header("Location");
			($access_token, $user_id) 		= $redirect =~ /access_token=(\w+).*?user_id=(\d+)/;
		}
	}
	else
	{
		($access_token, $user_id) 		= $response->previous()->header("Location") =~ /access_token=(\w+).*?user_id=(\d+)/;
	}

	return ('errcode' => 102,
		'errdesc' => 'Cannot parse acess token and user id!') unless ($access_token && $user_id);

										# Обновление cookie с m.vk.com в vk.com
	my ($remix_sid) = $browser->cookie_jar->as_string =~ /remixsid=(\w+)/;
	$browser->cookie_jar->set_cookie(3, "remixsid", $remix_sid, "/", "vk.com");	
	$response					= $browser->get("http://m.vk.com/id1");
	

	$self->{mid} 					= $user_id;
	$self->{access_token}				= $access_token;
	$self->{browser} 				= $browser;

	return ('errcode' => 0,
		'mid'	  => $user_id,
		'errdesc' => '');

}


#-----------------------------------------------------------------------------------------
#										Получения ссылки на объект-браузер
#										Rev1, 110605
sub interface
{
	my $self = shift;
	return $self->{browser};
}


#-----------------------------------------------------------------------------------------
#										Запрос к контакту с обработкой
#										капчи. Используется только в
#										логине
#										Rev4, 120310
#
sub postWithCaptcha
{
	my ($self, $link, $post, $headers) = @_;

	my $browser 				= $self->{browser};
	bless $browser, "LWP::UserAgent";

	my $response 				= $browser->post($link, $post, $headers);
	my $callback 				= $self->{captcha_callback};

	my ($sid, $diff, $cdata);
	
	while ($response->content =~ /captcha_sid/ or ($sid, $diff) = $response->decoded_content =~ /<!>2<!>(\d+)<!>(\d)/)
	{
		return undef unless (defined $callback);

		if ($response->content =~ /<!>2<!>(\d+)<!>(\d)/)
		{								# Новая капча
			$cdata->{'captcha_sid'}	= $sid;
			$cdata->{'difficult'} = $diff;
		}
		else
		{								# Старая капча
			utf8::encode($response->decoded_content);
			$cdata = decode_json($response->decoded_content);
			$sid = $cdata->{'captcha_sid'};
		}

		$cdata->{'difficult'} = 0 unless ($cdata->{'difficult'});

		$diff = abs (int $cdata->{'difficult'} - 1);
		$cdata->{'captcha_url'} = "http://vk.com/captcha.php?sid=$sid&s=$diff";
		$post->{'captcha_sid'} = $cdata->{'captcha_sid'};
		$post->{'captcha_key'} = &$callback($cdata);

		$response = $browser->post($link, $post, $headers);
	}

	return $response;
}


#-----------------------------------------------------------------------------------------
#										GET-запрос
#										Rev2, 120720
sub get
{
	my $self = shift;
	my $browser = $self->{browser};
	bless $browser, "LWP::UserAgent";

	my $response = $browser->get(@_);	
	return $response;
}


#-----------------------------------------------------------------------------------------
#										POST-запрос
#										Rev1, 120221
sub post
{
	my $self = shift;
	my $browser = $self->{browser};
	bless $browser, "LWP::UserAgent";

	my $response = $browser->post(@_);	
	return $response;
}

#-----------------------------------------------------------------------------------------
#										Запрос к API
#										Rev1, 120121
sub request {
	my ($self, $method, $params) = @_;

	my $browser = $self->{browser};
	bless $browser, "LWP::UserAgent";

	$params->{"access_token"} = $self->{access_token};

	my $response = $browser->post("https://api.vk.com/method/$method", $params);

	my $result;
	$result = decode_json($response->decoded_content);
										# Captcha is needed.
	if ($result->{error}->{error_code} and $result->{error}->{error_code} == 14)
	{
		my $callback = $self->{captcha_callback};
		my $answer = &$callback({ "captcha_url" => $result->{error}->{captcha_img},
		                          "captcha_sid" => $result->{error}->{captcha_sid}
		                        });
		$params->{captcha_sid} = $result->{error}->{captcha_sid};
		$params->{captcha_key} = $answer;
	        return $self->request($method, $params);
	}

	return $result;
}


1;

