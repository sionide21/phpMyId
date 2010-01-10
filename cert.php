<?php
/**
 * This file is similar to auth.php but has been pre_configured to use client
 * side certs.
 *
 * @package phpMyID
 * @author Ben Olive <sionide21@gmail.com>
 * @copyright 2010
 * @license http://www.gnu.org/licenses/gpl.html GNU Public License
 * @version 1.0
 */

session_name('phpMyID_Server');
@session_start();
if ($_SESSION['auth_url']) {
	if (isset ($_SERVER['REMOTE_USER'])) {
		$_SESSION['cert_number'] = $_SERVER['REMOTE_USER'];
		header('HTTP/1.1 302 Found');
		header('Location: ' . $_SESSION['auth_url']);
		exit(0);
	} else {
		header('HTTP/1.1 302 Found');
		// If we got to this page without authenticating, it is not a 
		// valid auth form and we can skip it.
		header('Location: ' . $_SESSION['auth_url'] . '&skip_cert=true');
		exit(0);
	}
} else {
	die('You may not access this mode directly.');
}
?>