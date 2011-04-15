package HVKAPI;

#    HVKAPI - class for vkontakte.ru API
#    Copyright (C) 2011 Hagall (asbrandr@jabber.ru)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

use warnings;
use strict;
use utf8;

use Digest::MD5 qw(md5 md5_hex);
use LWP::Simple;
use HTTP::Cookies;
use JSON;
use Data::Dumper;

use constant {
	ERROR_CAPTCHA => 666,
	ERROR_SECURITY => 102,
	ERROR_LOGIN    => 101,
};

our $VERSION = '0.01';
our $appId = 2248585;
our $appSettings = '16383';

our @ISA = qw(Exporter);
our @EXPORT_OK = qw(ERROR_CAPTCHA ERROR_SECURITY ERROR_LOGIN);
our %EXPORT_TAGS = (types => [qw(ERROR_CAPTCHA ERROR_SECURITY ERROR_LOGIN)]);

#-----------------------------------------------------------------------------------------
#							Конструктор класса.
#							Rev1, 110327
sub new {
	my $class = shift;
	my $self  = {};
	bless( $self, $class );

	($self->{api_id}, $self->{app_settings}, $self->{useragent}) = @_;
	$self->{useragent} || ($self->{useragent} = 'Mozilla/5.0 (X11; U; Linux i686; ru; rv:1.9.2.12) Gecko/20101027 Ubuntu/10.10');
	$self->{api_id} || ($self->{api_id} = $appId);
	$self->{app_settings} || ($self->{app_settings} = $appSettings);
	
	
	$self->{api_url} = 'http://api.vkontakte.ru/api.php';
	return $self;
}
#-----------------------------------------------------------------------------------------
#							Логин в API без компонента
#							Rev1, 110327
sub login
{
	my $self = shift;

	my ($ulogin, $upass, $captchaCallback) = @_;		
	
	my ($app_id, $app_settings) = ($self->{api_id}, $self->{app_settings});
	my $login = _encurl($ulogin);
	my $pass = _encurl($upass);
	
	my $browser = LWP::UserAgent->new();
	
	$browser->agent($self->{useragent});
	
							# Получаем app_hash
	my $response = $browser->get("http://vk.com/login.php?app=$app_id&layout=popup&type=browser&settings=$app_settings");
	return ('errcode' => 100, 
	        'errdesc' => 'Cannot parse app_hash!') unless ($response->content =~ /name="app_hash" value="(\w+)"/);

	$self->{app_hash} = $1;	
	
							# Проверяем на капчу
	
	$response = _postWithCaptcha($browser, "http://vkontakte.ru/login.php", {"op" => "a_login_attempt"}, $captchaCallback);

							# Получаем переменную s							
	$response = $browser->get("http://login.vk.com/?act=login&pass=$pass&email=$login&app_hash=$1&permanent=1&vk=");
	return ('errcode' => 101, 
	        'errdesc' => 'Incorrect login data!') unless ($response->content =~/name='s' value='(\w+)'/);
	
	$self->{sid} = $1;

							# Получаем параметры сессии и подтверждение настроек
	my $cookie = HTTP::Cookies->new();
	$cookie->set_cookie(1, 'remixsid', $1, '/', 'vkontakte.ru');
	$cookie->set_cookie(1, 'remixsid', $1, '/', 'vk.com');
	$browser->cookie_jar($cookie);
	$response = $browser->get("http://vkontakte.ru/login.php?app=$app_id&layout=popup&type=browser&settings=$app_settings");	
	
	unless ($response->content =~ /Login success/)
	{
		return ('errcode' => 102, 'errdesc' => 'Holy shit! Security check!') if ($response->content =~ /security_check/);
		return ('errcode' => 103, 'errdesc' => 'Cannot parse settings hash!') unless ($response->content =~ /app_settings_hash = '(\w+)'/);
		my $app_settings_hash = $1;
		return ('errcode' => 104, 'errdesc' => 'Cannot parse auth hash!') unless ($response->content =~ /auth_hash = '(\w+)'/);
		my $auth_hash = $1;
		
							# Логинимся (a_auth) с этим хешем	
		$response = $browser->post("http://vk.com/login.php", {'act' => 'a_auth',
		                                                       'app' => $app_id,
		                                                       'hash' => $auth_hash,
		                                                       'permanent' => '1'});
		                                                                          
		$self->{mid} = ($response->content =~ /"mid":(\d+)/)[0];		
		$self->{sid} = ($response->content =~ /"sid":"(\w+)"/)[0];
		$self->{secret} = ($response->content =~ /"secret":"(\w+)"/)[0];
		return ('errcode' => 105, 
		        'errdesc' => "Error parsing params (mid, sid, secret)!") unless ($self->{mid} && 
		                                                                         $self->{sid} && 
		                                                                         $self->{secret});

	                				# Сохраняем настройки приложения     
		$response = _postWithCaptcha($browser, "http://vk.com/apps.php?act=a_save_settings", 
											{"addMember" => "1",
		                                                                	"app_settings_32" => "1",
		                                                                	"app_settings_64" => "1",
		                                                               	 	"app_settings_128" => "1",
		                                                               	 	"app_settings_256" => "1",
		                                                                	"app_settings_512" => "1",
		                                                                	"app_settings_1024" => "1",
		                                                                	"app_settings_2048" => "1",
		                                                                	"app_settings_8192" => "1",
		                                                                	"app_settings_4096" => "1",
		                                                                	"hash" => $app_settings_hash,
		                                                                	"id" => $app_id}, $captchaCallback);
   		
 		return ('errcode' => 666, 'errdesc' => 'Captcha has been encountered!') unless defined $response;
 		
		return ('errcode' => 0, 'errdesc' => '', 'mid' => $self->{mid});
	}
	return ('errcode' => 106, 
	        'errdesc' => "Server didn't return correct redirect or settings hash page!") unless ($response->previous->is_redirect);
	
							# Декодируем mid, secret и т.д.
	my $rurl = _decurl($response->request->url);
	$self->{mid} = ($rurl =~ /"mid":(\d+)/)[0];
	$self->{sid} = ($rurl =~ /"sid":"(\w+)"/)[0];
	$self->{secret} = ($rurl =~ /"secret":"(\w+)"/)[0];
	return ('errcode' => 107, 
	        'errdesc' => "Error parsing params (mid, sid, secret)!") unless ($self->{mid} && $self->{sid} && $self->{secret});
	
	return ('errcode' => 0, 
	        'errdesc' => '', 
	        'mid' => $self->{mid});
}
#-----------------------------------------------------------------------------------------
#							Запрос к контакту с обработкой
#							капчи. Используется только в 
#							логине
#							Rev1, 110331
#	
sub _postWithCaptcha
{
	my ($browser, $link, $post, $callback) = @_;
	
	bless $browser, "LWP::UserAgent";
	
	my $response = $browser->post($link, $post);
	
	while ($response->content =~ /captcha_sid/)
	{
		return undef unless defined $callback;

		utf8::encode($response->content);
		my $cdata = decode_json($response->content);
		my $sid = $cdata->{'captcha_sid'};
		$cdata->{'difficult'} = 0 unless ($cdata->{'difficult'});
		
		my $diff = abs (int $cdata->{'difficult'} - 1);
		$cdata->{'captcha_url'} = "http://vkontakte.ru/captcha.php?sid=$sid&s=$diff";
		$post->{'captcha_sid'} = $cdata->{'captcha_sid'};
		$post->{'captcha_key'} = &$callback($cdata);
		$response = $browser->post($link, $post);
	}
	
	return $response;
}	
#-----------------------------------------------------------------------------------------
#							Запрос к API
#							Rev1, 110327
sub request {
	my $self   = shift;
	my $method = $_[0];

	my $params = $_[1];

	$params->{'api_id'}    = $self->{'api_id'};
	$params->{'v'}         = '3.0';
	$params->{'method'}    = $method;
	$params->{'format'}    = 'JSON';
	$params->{'random'}    = int rand 1000;
	
							# Заполняем подпись запроса - sig
	my $sig = $self->{mid};
        foreach my $k (sort keys %$params)
        {
		$sig .= $k.'='.$params->{$k};
	}
	$sig .= $self->{secret};
	$params->{'sig'} = md5_hex(encode_utf8($sig));
	$params->{'sid'} = $self->{sid};

							# Шлём запрос
	my $browser = LWP::UserAgent->new(agent => $self->{'useragent'});
	my $response = $browser->post($self->{'api_url'}, $params);
	utf8::encode($response->content);
	
							# Декодировка
	return decode_json($response->content);
}
#-----------------------------------------------------------------------------------------
#							urlencode и urldecode
#							Rev1, 110327
sub _encurl 
{
	my ($url) = @_;
	( defined $url ) || ( $url = "" );
	$url =~ s/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg;
	return $url;
}

sub _decurl
{
	my $url = shift;
	$url =~ s/\%([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;
	return $url;
}

1;   

