<?php
/**
 * Nextcloud - useraafrapidconnect
 *
 * This file is licensed under the Affero General Public License version 3 or
 * later. See the COPYING file.
 *
 * @author Adrian Lee <adrian.lee@qcif.edu.au>
 * @copyright Adrian Lee 2016
 */

namespace OCA\UserAafRapidConnect\AppInfo;

use OCP\AppFramework\App;

require_once __DIR__ . '/autoload.php';

$app = new App('useraafrapidconnect');
$container = $app->getContainer();

// $container->query('OCP\INavigationManager')->add(function () use ($container) {
// 	$urlGenerator = $container->query('OCP\IURLGenerator');
// 	$l10n = $container->query('OCP\IL10N');
// 	return [
// 		// the string under which your app will be referenced in Nextcloud
// 		'id' => 'useraafrapidconnect',
// 
// 		// sorting weight for the navigation. The higher the number, the higher
// 		// will it be listed in the navigation
// 		'order' => 10,
// 
// 		// the route that will be shown on startup
// 		'href' => $urlGenerator->linkToRoute('useraafrapidconnect.page.aaflogin'),
// 
// 		// the icon that will be shown in the navigation
// 		// this file needs to exist in img/
// 		'icon' => $urlGenerator->imagePath('useraafrapidconnect', 'app.svg'),
// 
// 		// the title of your application. This will be used in the
// 		// navigation or on the settings page of your app
// 		'name' => $l10n->t('User Aaf Rapid Connect'),
// 	];
// });
