<?php
/* phpMyID - A standalone, single user, OpenID Identity Provider
 *
 * by: CJ Niemira <siege (at) siege (dot) org>
 * (c) 2006-2007
 * http://siege.org/projects/phpMyID
 * Config File Version 2
 *
 * IF YOU HAVE NOT DONE SO, PLEASE READ THE README FILE FOR DIRECTIONS!!!
 */

$GLOBALS['profile'] = array(
	'auth_username'	=> 	'test',
	'auth_password' =>	'37fa04faebe5249023ed1f6cc867329b',
	'auth_realm'	=>	'phpMyID',

#	'debug'		=>	false,
#	'logfile'	=>	'/tmp/phpMyID.debug.log'
);

$GLOBALS['sreg'] = array (
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
include('MyID.php');
?>
