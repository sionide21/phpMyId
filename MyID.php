<?
/*
 * phpMyID - A standalone, single user, OpenID Identity Provider
 *
 * by: CJ Niemira <siege (at) siege (dot) org>
 * (c) 2006
 * http://siege.org/projects/phpMyID
 *
 * Version: 0.3
 *
 * This code is licensed under the GNU General Public License
 * http://www.gnu.org/licenses/gpl.html
 *
 *
 * *************************************************************************** *
 * CONFIGURATION
 * *************************************************************************** *
 * You must change these values:
 *	auth_username = login name
 *	auth_password = md5(username:phpMyID:password)
 *
 * Default username = 'test', password = 'test'
 */

$profile = array(
	'auth_username'	=> 	'test',
	'auth_password' =>	'e8358914a32e1ce3c62836db4babaa01'
);

/*
 * Optional - Simple Registration Extension:
 *
 *   If you would like to add any of the following optional registration
 *   parameters to your login profile, simply uncomment the line, and enter the
 *   correct values.
 *
 *   Details on the exact allowed values for these paramters can be found at:
 *   http://openid.net/specs/openid-simple-registration-extension-1_0.html
 */

$sreg = array (
#	'nickname'		=> 'Joe',
#	'email'			=> 'joe@example.com',
#	'fullname'		=> 'Joe Example',
#	'dob'			=> '1970-10-31',
#	'gender'		=> 'M',
#	'postcode'		=> '22000',
#	'country'		=> 'US',
#	'language'		=> 'en',
#	'timezone'		=> 'America/New_York'
);



/******************************************************************************/

/*
 * Internal configuration
 * DO NOT ALTER ANYTHING BELOW THIS POINT UNLESS YOU KNOW WHAT YOU ARE DOING!
 */

$idp_url = sprintf("%s://%s:%s%s",
		   ($_SERVER["HTTPS"] == 'on' ? 'https' : 'http'),
		   $_SERVER['SERVER_NAME'],
		   $_SERVER['SERVER_PORT'],
		   $_SERVER['PHP_SELF']);

$req_url = sprintf("%s://%s%s",
		   ($_SERVER["HTTPS"] == 'on' ? 'https' : 'http'),
		   $_SERVER['HTTP_HOST'],
		   $_SERVER["REQUEST_URI"]);

$profile['auth_domain'] = "$req_url $idp_url";
$profile['auth_realm'] = 'phpMyID';
$profile['lifetime'] = ((session_cache_expire() * 60) - 10);

$known = array(
	'assoc_types'	=> array('HMAC-SHA1'),

	'openid_modes'	=> array('associate',
				 'checkid_immediate',
				 'checkid_setup',
				 'check_authentication',
				 'error',
			 	 'logout'),

	'session_types'	=> array('',
				 'DH-SHA1'),

	'bigmath_types' => array('DH-SHA1'),
);

$g = 2;

$p = '15517289818147369747123225776371553991572480196691540447970779531405762' .
'9378541917580651227423698188993727816152646631438561595825688188889951272158' .
'8426754199503412587065565498035801048705376814767265132557470407658574792912' .
'9157233451064324509471500722962109419434978392598476037559498584825335930558' .
'5439638443';



/******************************************************************************/

/*
 * Runmode functions
 */

function associate_mode () {
	global $g, $known, $p, $profile;

	// Validate the request
	if (! isset($_POST['openid_mode']) || $_POST['openid_mode'] != 'associate')
		error_400();

	// Get the options, use defaults as necessary
	$assoc_type = (strlen($_POST['openid_assoc_type'])
		    && in_array($_POST['openid_assoc_type'], $known['assoc_types']))
			? $_POST['openid_assoc_type']
			: 'HMAC-SHA1';

	$session_type = (strlen($_POST['openid_session_type'])
		      && in_array($_POST['openid_session_type'], $known['session_types']))
			? $_POST['openid_session_type']
			: '';

	$dh_modulus = (strlen($_POST['openid_dh_modulus']))
		? $_POST['openid_dh_modulus']
		: ($session_type == 'DH-SHA1'
			? $p
			: null);

	$dh_gen = (strlen($_POST['openid_dh_gen']))
		? $_POST['openid_dh_gen']
		: ($session_type == 'DH-SHA1'
			? $g
			: null);

	$dh_consumer_public = (strlen($_POST['openid_dh_consumer_public']))
		? $_POST['openid_dh_consumer_public']
		: ($session_type == 'DH-SHA1'
			? error_post('dh_consumer_public was not specified')
			: null);

	// Create the associate id and shared secret now
	$lifetime = time() + $profile['lifetime'];

	// Create standard keys
	$keys = array(
		'assoc_type' => $assoc_type,
		'expires_in' => $profile['lifetime']
	);

	// If I can't handle bigmath, default to plaintext sessions
	if (in_array($session_type, $known['bigmath_types']) && ! extension_loaded('bcmath'))
		$session_type = null;

	// Add response keys based on the session type
	switch ($session_type) {
		case 'DH-SHA1':
			list ($assoc_handle, $shared_secret) = new_assoc($lifetime);

			// Compute the Diffie-Hellman stuff
			$private_key = random($dh_modulus);
			$public_key = bcpowmod($dh_gen, $private_key, $dh_modulus);
			$remote_key = long(base64_decode($dh_consumer_public));
			$ss = bcpowmod($remote_key, $private_key, $dh_modulus);

			$keys['assoc_handle'] = $assoc_handle;
			$keys['session_type'] = $session_type;
			$keys['dh_server_public'] = base64_encode(bin($public_key));
			$keys['enc_mac_key'] = base64_encode(x_or(sha1_20(bin($ss)), $shared_secret));

			break;

		default:
			list ($assoc_handle, $shared_secret) = new_assoc();

			$keys['assoc_handle'] = $assoc_handle;
			$keys['mac_key'] = base64_encode($shared_secret);
	}

	// Return the keys
	wrap_kv($keys);
}


function check_authentication_mode () {
	// Validate the request
	if (! isset($_POST['openid_mode']) || $_POST['openid_mode'] != 'check_authentication')
		error_400();

	$assoc_handle = strlen($_POST['openid_assoc_handle'])
		? $_POST['openid_assoc_handle']
		: error_post('Missing assoc_handle');

	$sig = strlen($_POST['openid_sig'])
		? $_POST['openid_sig']
		: error_post('Missing sig');

	$signed = strlen($_POST['openid_signed'])
		? $_POST['openid_signed']
		: error_post('Missing signed');

	// Prepare the return keys
	$keys = array(
		'openid.mode' => 'id_res'
	);

	// Invalidate the assoc handle if we need to
	if (strlen($_POST['openid_invalidate_handle'])) {
		destroy_assoc_handle($_POST['openid_invalidate_handle']);

		$keys['invalidate_handle'] = $_POST['openid_invalidate_handle'];
	}

	// Validate the sig by recreating the kv pair and signing
	$_POST['openid_mode'] = 'id_res';
	$tokens = '';
	foreach (explode(',', $signed) as $param) {
		$post = preg_replace('/\./', '_', $param);
		$tokens .= sprintf("%s:%s\n", $param, $_POST['openid_' . $post]);
	}

	// Add the sreg stuff, if we've got it
	foreach (explode(',', $sreg_required) as $key) {
			if (! isset($sreg[$key]))
				continue;
			$skey = 'sreg.' . $key;

			$tokens .= sprintf("%s:%s\n", $skey, $sreg[$key]);
			$keys[$skey] = $sreg[$key];
			$fields[] = $skey;
	}

	list ($shared_secret, $expires) = secret($assoc_handle);

	// A 'smart mode' id will have an expiration time set, don't allow it
	if ($shared_secret == false || is_numeric($expires)) {
		$keys['is_valid'] = 'false';

	} else {
		$ok = base64_encode(hmac($shared_secret, $tokens));
		$keys['is_valid'] = ($sig == $ok) ? 'true' : 'false';
	}

	// Return the keys
	wrap_kv($keys);
}


function checkid ( $wait ) {
	debug("checkid : $wait");
	global $idp_url, $known, $profile, $sreg, $user_authenticated;

	// Get the options, use defaults as necessary
	$return_to = strlen($_GET['openid_return_to'])
		? $_GET['openid_return_to']
		: error_400('Missing return_to');

	$identity = strlen($_GET['openid_identity'])
			? $_GET['openid_identity']
			: error_get($return_to, 'Missing identity');

	$assoc_handle = strlen($_GET['openid_assoc_handle'])
			? $_GET['openid_assoc_handle']
			: null;

	$trust_root = strlen($_GET['openid_trust_root'])
			? $_GET['openid_trust_root']
			: $return_to;

	$sreg_required = strlen($_GET['openid_sreg_required'])
			? $_GET['openid_sreg_required']
			: '';

	$sreg_optional = strlen($_GET['openid_sreg_optional'])
			? $_GET['openid_sreg_optional']
			: '';

	// required and optional make no difference to us
	$sreg_required .= ',' . $sreg_optional;

	$keys = array(
		'mode' => 'id_res'
	);

	// try to get the digest headers - what a PITA!
	if (version_compare(phpversion(), '5.0.0', 'lt')) {
		if (function_exists('apache_request_headers')) {
			$arh = apache_request_headers();
			$hdr = $arh['Authorization'];

		} elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
			$hdr = $_SERVER['HTTP_AUTHORIZATION'];

		} else {
			$hdr = null;
		}

		$digest = substr($hdr,0,7) == 'Digest '
			?  substr($hdr, strpos($hdr, ' ') + 1)
			: null;

	} else {
		$digest = empty($_SERVER['PHP_AUTH_DIGEST'])
			? null
			: $_SERVER['PHP_AUTH_DIGEST'];
	}

	$stale = false;

	// is the user trying to log in?
	if ($wait && ! is_null($digest) && $user_authenticated === false) {
		debug($digest);
		$hdr = array();

		// decode the Digest authentication headers
		preg_match_all('/(\w+)=(?:"([^"]+)"|([^\s,]+))/', $digest, $mtx, PREG_SET_ORDER);

		foreach ($mtx as $m)
			$hdr[$m[1]] = $m[2] ? $m[2] : $m[3];
		debug($hdr);

		if ($hdr['nonce'] != $_SESSION['uniqid'])
			$stale = true;

		if ($profile['auth_username'] == $hdr['username'] && ! $stale) {

			// the entity body should always be null in this case
			$entity_body = '';
			$a1 = $profile['auth_password'];
			$a2 = $hdr['qop'] == 'auth-int'
				? md5(implode(':', array($_SERVER['REQUEST_METHOD'], $hdr['uri'], md5($entity_body))))
				: md5(implode(':', array($_SERVER['REQUEST_METHOD'], $hdr['uri'])));
			$ok = md5(implode(':', array($a1, $hdr['nonce'], $hdr['nc'], $hdr['cnonce'], $hdr['qop'], $a2)));

			// successful login!
			if ($hdr['response'] == $ok) {
				$_SESSION['auth_username'] = $hdr['username'];
				$user_authenticated = true;

			// too many failures
			} elseif (strcmp($hdr['nc'], 5) > 0) {
				wrap_refresh($return_to . $q . 'openid.mode=cancel');
			}
		}
	}

	// make sure i am this identifier
	if ($identity != $idp_url) {
		if ($wait) {
			$keys['mode'] = 'cancel';
		} else {
			$keys['user_setup_url'] = $idp_url;
		}

	// if the user is not logged in, send the login headers
	} elseif ($user_authenticated === false) {
		if ($wait) {
			$uid = uniqid(mt_rand(1,9));
			$_SESSION['uniqid'] = $uid;

			header('HTTP/1.0 401 Unauthorized');
			header(sprintf('WWW-Authenticate: Digest qop="auth-int, auth", realm="%s", domain="%s", nonce="%s", opaque="%s", stale="%s", algorithm="MD5"', $profile['auth_realm'], $profile['auth_domain'], $uid, md5($profile['auth_realm']), $stale ? 'true' : 'false'));
			$q = strpos($return_to, '?') ? '&' : '?';
			wrap_refresh($return_to . $q . 'openid.mode=cancel');

		} else {
			$keys['user_setup_url'] = $idp_url;
		}

	// the user is logged in
	} else {
		// check the assoc handle
		list($shared_secret, $expires) = secret($assoc_handle);
		if ($shared_secret == false || (is_numeric($expires) && $expires < time())) {
			if ($assoc_handle != null)
				$keys['invalidate_handle'] = $assoc_handle;
			list ($assoc_handle, $shared_secret) = new_assoc();
		}

		$keys['identity'] = $idp_url;
		$keys['assoc_handle'] = $assoc_handle;
		$keys['return_to'] = $return_to;

		$fields = array_keys($keys);
		$tokens = '';
		foreach ($fields as $key)
			$tokens .= sprintf("%s:%s\n", $key, $keys[$key]);

		// add sreg keys
		foreach (explode(',', $sreg_required) as $key) {
			if (! isset($sreg[$key]))
				continue;
			$skey = 'sreg.' . $key;

			$tokens .= sprintf("%s:%s\n", $skey, $sreg[$key]);
			$keys[$skey] = $sreg[$key];
			$fields[] = $skey;
		}

		$keys['signed'] = implode(',', $fields);
		$keys['sig'] = base64_encode(hmac($shared_secret, $tokens));
	}

	wrap_location($return_to, $keys);
}


function checkid_immediate_mode () {
	if (! isset($_GET['openid_mode']) || $_GET['openid_mode'] != 'checkid_setup')
		error_500();

	checkid(false);
}


function checkid_setup_mode () {
	if (! isset($_GET['openid_mode']) || $_GET['openid_mode'] != 'checkid_setup')
		error_500();

	checkid(true);
}


function error_mode () {
	isset($_REQUEST['openid_error']) 
		? wrap_html($_REQUEST['openid_error'])
		: error_500();
}


function logout_mode () {
	global $idp_url, $user_authenticated;

	if (! $user_authenticated)
		error_400();

	session_destroy();
	wrap_refresh($idp_url);
}


function no_mode () {
	global $idp_url, $user_authenticated;

	wrap_html('This is an OpenID server endpoint. For more information, see http://openid.net/<br/>' . $idp_url);
}



/*
 * Support functions
 */
function append_openid ($array) {
	$keys = array_keys($array);
	$vals = array_values($array);

	$r = array();
	for ($i=0; $i<sizeof($keys); $i++)
		$r['openid.' . $keys[$i]] = $vals[$i];
	return $r;
}

// Borrowed from http://php.net/manual/en/function.bcpowmod.php#57241
if (! function_exists('bcpowmod')) {
function bcpowmod ($value, $exponent, $mod) {
	$r = 1;
	while (true) {
		if (bcmod($exponent, 2) == "1")
			break;
		if (($exponent = bcdiv($exponent, 2)) == '0')
			break;
		$value = bcmod(bcmul($value, $value), $mod);
	}
	return $r;
}}


// Borrowed from PHP-OpenID; http://openidenabled.com
function bin ($n) {
	$bytes = array();
	while (bccomp($n, 0) > 0) {
		array_unshift($bytes, bcmod($n, 256));
		$n = bcdiv($n, pow(2,8));
	}

	if ($bytes && ($bytes[0] > 127))
		array_unshift($bytes, 0);

	$b = '';
	foreach ($bytes as $byte)
		$b .= pack('C', $byte);

	return $b;
}


function debug ($x) {
	return true; // debugging off
	if (is_array($x)) {
		ob_start();
		print_r($x);
		$x = ob_get_clean();
	}

	error_log($x . "\n", 3, "/var/tmp/phpMyID.debug.log");
}


function destroy_assoc_handle ( $id ) {
	debug("Destroy $id");
	$old = session_id();
	session_write_close();

	session_id($id);
	session_start();
	session_destroy();

	session_id($old);
	session_start();
}


function error_400 ( $message = 'Bad Request' ) {
	header("HTTP/1.1 400 Bad Request");
	wrap_html($message);
}


function error_500 ( $message = 'Internal Server Error' ) {
	header("HTTP/1.1 500 Internal Server Error");
	wrap_html($message);
}


function error_get ( $url, $message = 'Bad Request') {
	wrap_location($url, array('mode' => 'error', 'error' => $message));
}


function error_post ( $message = 'Bad Request' ) {
	header("HTTP/1.1 400 Bad Request");
	echo ('error:' . $message);
	exit(0);
}


// Borrowed from - http://php.net/manual/en/function.sha1.php#39492
function hmac($key, $data, $hash = 'sha1_20') {
	$blocksize=64;

	if (strlen($key) > $blocksize)
		$key = $hash($key);

	$key = str_pad($key, $blocksize,chr(0x00));
	$ipad = str_repeat(chr(0x36),$blocksize);
	$opad = str_repeat(chr(0x5c),$blocksize);

	$h1 = $hash(($key ^ $ipad) . $data);
	$hmac = $hash(($key ^ $opad) . $h1);
	return $hmac;
}


if (! function_exists('http_build_query')) {
function http_build_query ($array) {
	$r = array();
	foreach ($array as $key => $val)
		$r[] = sprintf('%s=%s', $key, urlencode($val));
	return implode('&', $r);
}}


// Borrowed from PHP-OpenID; http://openidenabled.com
function long($b) {
	$bytes = array_merge(unpack('C*', $b));
	$n = 0;
	foreach ($bytes as $byte) {
		$n = bcmul($n, bcpow(2,8));
		$n = bcadd($n, $byte);
	}
	return $n;
}


function new_assoc ( $expiration = null ) {
	$old = session_id();
	session_write_close();

	session_start();
	session_regenerate_id('false');

	$new = session_id();
	$shared_secret = new_secret();

	$_SESSION = array();
	$_SESSION['expiration'] = $expiration;
	$_SESSION['shared_secret'] = base64_encode($shared_secret);
	session_write_close();

	session_id($old);
	session_start();

	return array($new, $shared_secret);
}


function new_secret () {
	$r = '';
	for($i=0; $i<20; $i++)
		$r .= chr(mt_rand(0, 255));
	debug("New secret >>>$r<<<\nsize = " . strlen($r));
	return $r;
}


function random ( $max ) {
	if (strlen($max) < 4)
		return mt_rand(1, $max - 1);

	$r = '';
	for($i=1; $i<strlen($max) - 1; $i++)
		$r .= mt_rand(0,9);
	$r .= mt_rand(1,9);

	return $r;
}


function secret ( $handle ) {
	$len = strlen(session_id());
	$regex = '/^\w{' . $len . '}$/';

	debug("Get secret for '$handle', which must match '$regex'");

	if (! preg_match($regex, $handle))
		return array(false, 0);

	$sid = session_id();
	session_write_close();

	session_id($handle);
	session_start();

	$secret = session_is_registered('shared_secret')
		? base64_decode($_SESSION['shared_secret'])
		: false;

	$expiration = session_is_registered('expiration')
		? $_SESSION['expiration']
		: null;

	session_write_close();

	session_id($sid);
	session_start();

	debug("expires '$expiration'");
	return array($secret, $expiration);
}


// Borrowed from PHP-OpenID; http://openidenabled.com
function sha1_20 ($v) {
	$hex = sha1($v);
	$r = '';
	for ($i = 0; $i < 40; $i += 2) {
		$hexcode = substr($hex, $i, 2);
		$charcode = (int)base_convert($hexcode, 16, 10);
		$r .= chr($charcode);
	}
	return $r;
}


function wrap_html ( $message ) {
	global $idp_url, $req_url;

	header('Content-Type: text/html; charset=UTF-8');
	echo '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
<title>phpMyID</title>
<link rel="openid.server" href="' . $req_url . '" />
<link rel="openid.delegate" href="' . $idp_url . '" />
</head>
<body>
<p>' . $message . '</p>
</body>
</html>
';

	exit(0);
}


function wrap_kv ( $keys ) {
	debug($keys);
	header('Content-Type: text/plain; charset=UTF-8');
	foreach ($keys as $key => $value)
		printf("%s:%s\n", $key, $value);

	exit(0);
}


function wrap_location ($url, $keys) {
	$keys = append_openid($keys);
	debug($keys);

	$q = strpos($url, '?') ? '&' : '?';
	header('Location: ' . $url . $q . http_build_query($keys));
	debug('Location: ' . $url . $q . http_build_query($keys));
	exit(0);
}


function wrap_refresh ($url) {
	header('Content-Type: text/html; charset=UTF-8');
	echo '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
<title>phpMyID</title>
<meta http-equiv="refresh" content="0;url=' . $url . '">
</head>
<body>
<p>Redirecting to <a href="' . $url . '">' . $url . '</a></p>
</body>
</html>
';

	exit(0);
}


function x_or ($a, $b) {
	$r = "";

	for ($i = 0; $i < strlen($b); $i++)
		$r .= $a[$i] ^ $b[$i];
	debug("Xor >>>$r<<< : " . strlen($r));
	return $r;
}



/*
 * App Initialization
 */

// Start the user session
session_name('phpMyID_Server');
session_set_cookie_params(0, dirname($_SERVER['PHP_SELF']), $profile['domain']);
session_start();


// Decide if the user is authenticated
$user_authenticated = (isset($_SESSION['auth_username'])
		    && $_SESSION['auth_username'] == $profile['auth_username'])
		? true
		: false;


// Decide which runmode, based on user request or default
$run_mode = (isset($_REQUEST['openid_mode'])
	  && in_array($_REQUEST['openid_mode'], $known['openid_modes']))
	? $_REQUEST['openid_mode']
	: 'no';


// Run in the determined runmode
debug("mode: $run_mode " . time());
debug($_REQUEST);
eval($run_mode . '_mode();');
?>
