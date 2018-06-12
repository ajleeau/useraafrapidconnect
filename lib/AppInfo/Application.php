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

use \OCP\AppFrameWork\App;

use \OCA\UserAafRapidConnect\Controller\PageController;

class Application extends App {
    
    public function __construct(array $urlParams=array()) {
        parent::__construct('useraafrapidconnect',$urlParams);

        $container = $this->getContainer();

        $container->registerService('PageController', function($c) {
            return new PageController(
                $c->query('AppName'),
                $c->query('Request'),
                $c->query('Config'),
                $c->query('Session'),
		$c->query('UserManager'),
		$c->query('UserSession'),
		$c->query('URLGenerator'),
		$c->query('Logger')
            );
        });
    }

}
