<?php
/*
 * phpMyID - A standalone, single user, OpenID Identity Provider
 *
 * by: CJ Niemira <siege (at) siege (dot) org>
 * (c) 2006
 * http://siege.org/projects/phpMyID
 *
 * Config File Version 1
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
	'auth_password' =>	'37fa04faebe5249023ed1f6cc867329b'
);

/*
 * Optional - Simple Registration Extension:

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
if (! defined('PHPMYID_STARTED')) include('MyID.php');
?>
