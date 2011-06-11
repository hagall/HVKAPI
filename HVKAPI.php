<?php
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

# Version 0.2 (Rev2, 110605)

define('DEFAULT_APP', 2256065);
define('DEFAULT_AGENT', 'Mozilla/5.0 (X11; U; Linux i686; ru; rv:1.9.2.12) Gecko/20101027 Ubuntu/10.10');
define('API_URL', "http://api.vkontakte.ru/api.php");
define('REQUESTING_SETTINGS', 16383);

# Константы
define('ERROR_CAPTCHA',  666);
define('ERROR_SECURITY',  102);
define('ERROR_LOGIN',  101);

class hvkapi {
	var $useragent;							# Юзерагент.
	var $app_id;							# Ид приложения
	var $secret;							# Поле secret для приложения
	var $sid;							# Ид сессии
	
#---------------------------------------------------------------------------------------------------------	
									# Конструктор класса
									# Rev1, 110331
	function hvkapi($captchaCallback = '', $app_id = DEFAULT_APP) 
	{
		$this->captcha_callback = $captchaCallback;
		$this->app_id = $app_id;
	}
#---------------------------------------------------------------------------------------------------------	
									# Логин в контакте через API
									# Rev1, 110331	
	function Login($email, $password)
	{
		$result = array();
		$result['errcode'] = 0;
		$result['errdesc'] = 0;		

		$app_id = $this->app_id;
		$captchaCallback = $this->captcha_callback;
		
		$app_settings = REQUESTING_SETTINGS;
									# Получаем app_hash		
		$res = file_get_contents("http://vk.com/login.php?app=$app_id&layout=popup&type=browser&settings=$app_settings");

		if (!preg_match('#name="app_hash" value="(\w+)"#', $res, $found))
		{
			$result['errcode'] = 100;
			$result['errdesc'] = 'Cannot parse app_hash!';
			return $result;
		}		
		$app_hash = $found[1];
									# Проверяем на капчу
		$res = $this->_requestWithCaptcha("vkontakte.ru", 
		                                  "http://vkontakte.ru/login.php", '', 'op=a_login_attempt', $captchaCallback);		                                  
		                                  									
									# Получаем переменную s		
		$res = $this->_request("login.vk.com", "http://login.vk.com/", '', 
		                       "act=login&pass=".urlencode($password)."&email=".urlencode($email)."&app_hash=$app_hash&al_test=14&permanent=1");

		if (!preg_match("#name='s' value='(\w+)'#", $res['content'], $found))
		{
			$result['errcode'] = 101;
			$result['errdesc'] = 'Incorrect login data!';
			return $result;
		}
		
		$this->sid = $found[1];
		$sid = $found[1];
									# Получаем параметры сессии и подтверждение настроек		
		$cookie = "remixsid=$sid;";
		$res = $this->_request("vkontakte.ru", "/login.php?app=$app_id&layout=popup&type=browser&settings=$app_settings", $cookie, '');

		if (!preg_match("/Location: (.*)\n/Uis", $res['content'], $found))
		{
		
									# Проверяем на бан по айпишнику
			if (substr_count($res['content'], 'security_check') > 0)
			{
				$result['errcode'] = 102;
				$result['errdesc'] = 'Security check!';
				return $result;
			}
									# Парсим app_settings_hash
			if (!preg_match("#app_settings_hash = '(\w+)'#", $res['content'], $settings_hash))
			{
				$result['errcode'] = 103;
				$result['errdesc'] = 'Cannot parse app settings hash!';
				return $result;
			}
			$settings_hash = $settings_hash[1];
			
									# Парсим auth_hash
			if (!preg_match("#auth_hash = '(\w+)'#", $res['content'], $auth_hash))
			{
				$result['errcode'] = 104;
				$result['errdesc'] = 'Cannot parse auth hash!';
				return $result;
			}
			$auth_hash = $auth_hash[1];
			
  
									# Сохраняем настройки приложения
									                       
			$res = $this->_requestWithCaptcha("vk.com", "/apps.php?act=a_save_settings", $cookie, 
			                       "addMember=1&app_settings_32=1&app_settings_64=1&".
			                       "app_settings_128=1&app_settings_256=1&app_settings_512=1&".
			                       "app_settings_1024=1&app_settings_2048=1&app_settings_4096=1&".
			                       "app_settings_8192=1&hash=$settings_hash&id=$app_id", $captchaCallback);
			                       
			if ($res == null)
			{
				$result['errcode'] = 666;
				$result['errdesc'] = 'Captcha has been encountered!';
				return $result;				
			}

									# Логинимся (a_auth) с этим хешем
			$res = $this->_request("vk.com", "http://vk.com/login.php", $cookie, 
			                       "act=a_auth&app=$app_id&hash=$auth_hash&permanent=1");

			preg_match('/"mid":(\d+)/', $res['content'], $mid);
			preg_match('/"sid":"(\w+)"/', $res['content'], $sid);
			preg_match('/"secret":"(\w+)"/', $res['content'], $secret);
			                      				# ...И сохраняем параметры сессии
			if ((count($mid) < 2) ||
			    (count($sid) < 2) ||
			    (count($secret) < 2))
			{
				$result['errcode'] = 105;
				$result['errdesc'] = 'Error parsing params (mid, sid, secret)!';
				return $result;		
			}
			$this->sid = $sid[1];
			$this->mid = $mid[1];
			$this->secret = $secret[1];
			
			return $result;
		}
									# Декодируем mid, secret и т.д.
		if (!preg_match('/"mid":(\d+)/', urldecode($found[1]), $mid) ||
		    !preg_match('/"sid":"(\w+)"/', urldecode($found[1]), $sid) ||
		    !preg_match('/"secret":"(\w+)"/', urldecode($found[1]), $secret))
		{
			$result['errcode'] = 107;
			$result['errdesc'] = 'Error parsing params (mid, sid, secret)!';
			return $result;		
		}
		
		$this->sid = $sid[1];
		$this->mid = $mid[1];
		$this->secret = $secret[1];
		
		return $result;				
	}									
#---------------------------------------------------------------------------------------------------------	
									# Запрос к API
									# Rev1, 110331	
	function request($method, $params = false) 
	{
		if (!$params) $params = array(); 
		$params['api_id'] = $this->app_id;
		$params['v'] = '3.0';
		$params['method'] = $method;
		$params['format'] = 'json';
		$params['random'] = rand(0,10000);
		
		ksort($params);
		$sig = $this->mid;
		foreach($params as $k=>$v) 
		{
			$sig .= $k.'='.$v;
		}
		
		$sig .= $this->secret;
		$params['sig'] = md5($sig);
		$params['sid'] = $this->sid;
		
		$query = API_URL.'?'.$this->params($params);
		$res = file_get_contents($query);
		
		$jsond = json_decode($res, true);
		if (array_key_exists("error", $jsond) && $jsond['error']['error_code'] == 14)
		{
			$callback = $this->captchaCallback;
			$cparams = array();
			$cparams['captcha_url'] = $jsond['error']['captcha_img'];
			$cparams['captcha_sid'] = $jsond['error']['captcha_sid'];
			
			$params['captcha_sid'] = $jsond['error']['captcha_sid'];
			$params['captcha_key'] = call_user_func($callback, $cparams);
			return request($method, $params);
		}
		return $jsond;
	}
#---------------------------------------------------------------------------------------------------------	
									# Хуита для слияния параметров
									# Rev1, 110331	
	function params($params) 
	{
		$pice = array();
		foreach($params as $k=>$v) 
		{
			$pice[] = $k.'='.urlencode($v);
		}
		return implode('&',$pice);
	}
#---------------------------------------------------------------------------------------------------------	
									# Запрос к контакту, используется
									# в процедуре логина
									# Rev1, 110331	
	function _request($host, $link, $cookie, $post)
	{
		$result = array();
									# Заполняем параметры запроса
		$headers = "Host: $host\n".
			   "User-Agent: ".DEFAULT_AGENT."\n".
			   "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8\n".
			   "Accept-Language: ru,en-us;q=0.7,en;q=0.3\n".
			   "Accept-Charset: windows-1251,utf-8;q=0.7,*;q=0.7\n".
			   "Keep-Alive: 300\n".
			   "Connection: close\n";
		
		if ($cookie)
			$headers .= "Cookie: $cookie\n";
		
		$reqstr = '';	   
		if ($post)
			$reqstr = "POST $link HTTP/1.1\n".$headers."Content-Type: application/x-www-form-urlencoded\nContent-Length: ".strlen($post)."\n\n$post\n\n";
		else
			$reqstr = "GET $link HTTP/1.1\n".$headers."\n\n";			   		
									# Коннект к серверу, отправляем данные
    		$fp = fsockopen($host, 80, $errno, $errstr, 30);
    		if (!$fp)
    		{
    			$result['ok'] = false;
    			$result['errno'] = $errno;
    			$result['errdesc'] = $errdesc;
    			return $result;
    		}
    		fputs($fp, $reqstr);
    		
    		$resp = "";
    		while (!feof($fp))
    			$resp .= fgets($fp, 1024);
    		fclose($fp);
    		
    		$result['ok'] = true;
    		$result['content'] = $resp;
    		return $result;
	}
#---------------------------------------------------------------------------------------------------------	
#									Запрос к контакту с обработкой
#									капчи. Используется только в 
#									логине
#									Rev1, 110331	
	function _requestWithCaptcha($host, $link, $cookie, $post, $callback)
	{
		$res = $this->_request($host, $link, $cookie, $post);
		if (!$res['content']) return null;
		while (preg_match('#"captcha_sid":"(\d+)"#', $res['content'], $cvars))
		{
			preg_match('#"difficult":(\d+)#', $res['content'], $diff);
									# Т.к. difficulcy приходится инвертировать
			if (count($diff) < 2)
				$diff = 0;
			else
				$diff = $diff[1];
			$params = array();
			$params['difficult'] = $diff;
			$params['captcha_sid'] = $cvars[1];
			$params['captcha_url'] = "http://vkontakte.ru/captcha.php?sid={$cvars[1]}&s=".(abs($diff - 1));
			if (!$callback) return null;
			$answer = call_user_func($callback, $params);
			$res = $this->_request($host, $link, $cookie, $post."&captcha_sid={$cvars[1]}&captcha_key=$answer");
		}
		
		return $res;
	}
	
}

?>
