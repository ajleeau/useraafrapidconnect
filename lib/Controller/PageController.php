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

namespace OCA\UserAafRapidConnect\Controller;

use \Firebase\JWT\JWT;
use \Firebase\JWT\BeforeValidException;
use \Firebase\JWT\ExpiredException;
use \Firebase\JWT\SignatureInvalidException;
use OC\User;
use OC\User\Session;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Controller;
use OCP\IConfig;
use OCP\ILogger;
use OCP\IRequest;
use OCP\ISession;
use OCP\IServerContainer;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OC_Util;
use OC\Hooks\Emitter;
use Symfony\Component\EventDispatcher\GenericEvent;


class PageController extends Controller {

    private $urlgenerator;

    private $usermanager;

    private $userbackend;

    private $usersession;

    private $session;

    private $config;

    private $logger;

    private $activeuser;

    public function __construct($appName, IRequest $request, IConfig $config, ISession $session, IUserManager $userManager, IUserSession $userSession, IURLGenerator $urlGenerator, ILogger $logger) {
	parent::__construct($appName, $request);
	$this->config = $config;
        $this->session = $session;
        $this->urlgenerator = $urlGenerator;
        $this->usermanager = $userManager;
        $this->usersession = $userSession;
        $this->logger = $logger;

    }

    /**
     * @NoAdminRequired
     * @NoCSRFRequired
     * @PublicPage
     * @UseSession
     * @OnlyUnauthenticatedUsers
     *
     */
    public function aaflogin($assertion) {

	$parameters = array();
	$rawJSONwebToken = $assertion;

        \OCP\Util::writeLog('OC_useraafrapidconnect', 'rawJSONwebToken: '.$rawJSONwebToken, \OCP\Util::DEBUG);

	$prefix = 'assertion=';
	$encodedJSONwebToken = $rawJSONwebToken;
        $secretkey =
	    \OC::$server->getConfig()->getSystemValue('JWT_secret_key');
	JWT::$leeway = 60;
	try {
       	    $decoded =
                JWT::decode($encodedJSONwebToken, $secretkey, array('HS256'));
	}
	catch (\Exception $e) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'JWT::decode exception: '.$e->getMessage(), \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'JWT::decode exception';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
        }
	catch (\UnexpectedValueException $e) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'JWT::decode exception: '.$e->getMessage(), \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'JWT::decode exception';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
        }
	catch (\BeforeValueException $e) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'JWT::decode BeforeValueException: '.$e->getMessage(), \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'JWT::decode BeforeValueException';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
        }
	catch (\ExpiredException $e) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'JWT::decode ExpiredException: '.$e->getMessage(), \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'JWT::decode ExpiredException';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
        }
	catch (\SignatureInvalidException $e) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'JWT::decode SignatureInvalidException: '.$e->getMessage(), \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'JWT::decode SignatureInvalidException';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
        }

	if (is_null($decoded)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'Decoded JWT is null', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'Decoded JWT is null';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}

	$decoded_array = json_decode(json_encode($decoded), true);
	if (!array_key_exists('typ', $decoded_array)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'typ entry non-existent in decoded array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'typ entry non-existent in decoded array';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}

        $typ = $decoded_array['typ'];
	if (is_null($typ)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'Missing typ string', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'Missing typ string';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}

        \OCP\Util::writeLog('OC_useraafrapidconnect', 'typ: '.$typ, \OCP\Util::DEBUG);

        if ($typ !== 'authnresponse') {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'typ not "authnresponse"', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'typ not authnresponse';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
        }
	if (!array_key_exists('iss', $decoded_array)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'iss entry non-existent in decoded array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'iss entry non-existent';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        $iss = $decoded_array['iss'];
	if (is_null($iss)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'iss string is missing', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'iss string is missing';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}

	$expected_iss = \OC::$server->getConfig()->getSystemValue('JWT_expected_iss');

        \OCP\Util::writeLog('OC_useraafrapidconnect', 'iss: '.$iss, \OCP\Util::DEBUG);

	if ($iss !== $expected_iss) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'Expecting iss: '.$expected_iss, \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'iss mismatch';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
        }

	if (!array_key_exists('aud', $decoded_array)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'aud entry non-existent in decoded array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'aud entry non-existent in decode array';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        $aud = $decoded_array['aud'];
	if (is_null($aud)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'aud string is missing', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'aud string is missing';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
	$expected_aud = \OC::$server->getConfig()->getSystemValue('JWT_expected_aud');

        \OCP\Util::writeLog('OC_useraafrapidconnect', 'aud: '.$aud, \OCP\Util::DEBUG);

	if ($aud !== $expected_aud) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'Expecting aud: '.$expected_aud, \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'aud mismatch';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
        }
	if (!array_key_exists('jti', $decoded_array)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'jti entry non-existent in decoded array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'jti entry non-existent in decode array';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        $jti = $decoded_array['jti'];
	if (is_null($jti)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'jti string is missing', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'jti string is missing';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        \OCP\Util::writeLog('OC_useraafrapidconnect', 'jti: '.$jti, \OCP\Util::DEBUG);

	if (!array_key_exists('sub', $decoded_array)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'sub entry non-existent in decoded array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'sub entry non-existent in decode array';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        $sub = $decoded_array['sub'];
	if (is_null($sub)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'sub is null', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'sub is null';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        \OCP\Util::writeLog('OC_useraafrapidconnect', 'sub: '.$sub, \OCP\Util::DEBUG);

	$attrs = $decoded_array['https://aaf.edu.au/attributes'];
	if (is_null($attrs)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'attrs is null', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'attrs is null';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}

	if (!array_key_exists('edupersontargetedid', $attrs)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'edupersontargetedid entry non-existent in attrs array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'edupersontargetedid entry non-existent in attrs array';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
	$edupersontargetedid = $attrs['edupersontargetedid'];
	if (is_null($edupersontargetedid)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'edupersontargetedid string is missing', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'edupersontargetedid string is missing';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        \OCP\Util::writeLog('OC_useraafrapidconnect', 'edupersontargetedid: '.$edupersontargetedid, \OCP\Util::DEBUG);

	if (!array_key_exists('cn', $attrs)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'cn entry non-existent in attrs array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'cn entry non-existent in attrs array';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
	$cn = $attrs['cn'];
	if (is_null($cn)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'cn string is missing', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'cn string is missing';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        \OCP\Util::writeLog('OC_useraafrapidconnect', 'cn: '.$cn, \OCP\Util::DEBUG);

	if (!array_key_exists('displayname', $attrs)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'displayname entry non-existent in attrs array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'displayname entry non-existent in attrs array';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
	$displayname = $attrs['displayname'];
	if (is_null($displayname)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'displayname string is missing', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'displayname string is missing';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        \OCP\Util::writeLog('OC_useraafrapidconnect', 'displayname: '.$displayname, \OCP\Util::DEBUG);

	if (!array_key_exists('mail', $attrs)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'mail entry non-existent in attrs array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'mail entry non-existent in attrs array';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
	$mail = $attrs['mail'];
	if (is_null($mail)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'mail string is missing', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'mail string is missing';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        \OCP\Util::writeLog('OC_useraafrapidconnect', 'mail: '.$mail, \OCP\Util::DEBUG);

	if (!array_key_exists('edupersonscopedaffiliation', $attrs)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'edupersonscopedaffiliation entry non-existent in attrs array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'edupersonscopedaffiliation entry non-existent in attrs array';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
	$edupersonscopedaffiliation = $attrs['edupersonscopedaffiliation'];
	if (is_null($edupersonscopedaffiliation)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'edupersonscopedaffiliation string is missing', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'edupersonscopedaffiliation string is missing';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        \OCP\Util::writeLog('OC_useraafrapidconnect', 'edupersonscopedaffiliation: '.$edupersonscopedaffiliation, \OCP\Util::DEBUG);

	if (!array_key_exists('edupersonprincipalname', $attrs)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'edupersonprincipalname entry non-existent in attrs array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'edupersonprincipalname entry non-existent in attrs array';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
	$edupersonprincipalname = $attrs['edupersonprincipalname'];
	if (is_null($edupersonprincipalname)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'edupersonprincipalname string is missing', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'edupersonprincipalname string is missing';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        \OCP\Util::writeLog('OC_useraafrapidconnect', 'edupersonprincipalname: '.$edupersonprincipalname, \OCP\Util::DEBUG);

	if (!array_key_exists('auedupersonsharedtoken', $attrs)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'auedupersonsharedtoken entry non-existent in attrs array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'auedupersonsharedtoken entry non-existent in attrs array';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
	// $auedupersonsharedtoken = $attrs['auedupersonsharedtoken'];
	if (is_null($auedupersonsharedtoken)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'auedupersonsharedtoken string is missing', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'auedupersonsharedtoken string is missing';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        \OCP\Util::writeLog('OC_useraafrapidconnect', 'auedupersonsharedtoken: '.$auedupersonsharedtoken, \OCP\Util::DEBUG);

	if (!array_key_exists('givenname', $attrs)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'givenname entry non-existent in attrs array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'givenname entry non-existent in attrs array';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
	$givenname = $attrs['givenname'];
	if (is_null($givenname)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'givenname string is missing', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'givenname string is missing';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        \OCP\Util::writeLog('OC_useraafrapidconnect', 'givenname: '.$givenname, \OCP\Util::DEBUG);

	if (!array_key_exists('surname', $attrs)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'surname entry non-existent in attrs array', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'surname entry non-existent in attrs array';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
	$surname = $attrs['surname'];
	if (is_null($surname)) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'surname string is missing', \OCP\Util::ERROR);
	    $parameters['internalexception'] = 'surname string is missing';
            // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
        \OCP\Util::writeLog('OC_useraafrapidconnect', 'surname: '.$surname, \OCP\Util::DEBUG);

        $redirecturl = \OC::$server->getConfig()->getSystemValue('redirecturlonaaffault');
        $apiusername = \OC::$server->getConfig()->getSystemValue('candle_api_username');
        $apipassword = \OC::$server->getConfig()->getSystemValue('candle_api_password');
        $apiurl = \OC::$server->getConfig()->getSystemValue('candle_api_url');

	$apiurl = $apiurl.$auedupersonsharedtoken;
        $ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $apiurl);
	curl_setopt($ch, CURLOPT_TIMEOUT, 30);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	curl_setopt($ch, CURLOPT_USERPWD, $apiusername.':'.$apipassword);

        \OCP\Util::writeLog('OC_useraafrapidconnect', 'apiurl: '.$apiurl, \OCP\Util::DEBUG);
        \OCP\Util::writeLog('OC_useraafrapidconnect', 'apiusername: '.$apiusername, \OCP\Util::DEBUG);
        \OCP\Util::writeLog('OC_useraafrapidconnect', 'apipassword: '.$apipassword, \OCP\Util::DEBUG);

	$curlresult = curl_exec($ch);
	$curlinfo = curl_getinfo($ch);
	$curlhttpcode = $curlinfo['http_code'];
	if ($curlhttpcode !== NULL) {
            \OCP\Util::writeLog('OC_useraafrapidconnect', 'HTTP code:'.$curlhttpcode, \OCP\Util::DEBUG);
	    if ($curlhttpcode !== 200) {
                \OCP\Util::writeLog('OC_useraafrapidconnect', 'HTTP code is not OK', \OCP\Util::ERROR);
		curl_close($ch);
	        $parameters['usernotfoundincandle'] = 'user not found in candle';
                // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	        return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
            }
	    else {
                \OCP\Util::writeLog('OC_useraafrapidconnect', 'curlresult: '.$curlresult, \OCP\Util::DEBUG);
		
		$curlresultarray = json_decode($curlresult, true);
		$qsacresult = $curlresultarray['qsac'];
		if ($qsacresult === NULL) {
		    curl_close($ch);
	    	    \OCP\Util::writeLog('OC_useraafrapidconnect', 'qsacresult is null', \OCP\Util::ERROR);
	            $parameters['internalexception'] = 'qsacresult is null';
                    // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
		}
		$username = $qsacresult['username'];
		if ($username === NULL) {
		    curl_close($ch);
	    	    \OCP\Util::writeLog('OC_useraafrapidconnect', 'username is null', \OCP\Util::ERROR);
	            $parameters['internalexception'] = 'username is null';
                    // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
		}
		$qsacenabled = $curlresultarray['enabled'];

	        \OCP\Util::writeLog('OC_useraafrapidconnect', 'username: '.$username, \OCP\Util::DEBUG);
	        \OCP\Util::writeLog('OC_useraafrapidconnect', 'qsacenabled: '.$qsacenabled, \OCP\Util::DEBUG);
		if ($qsacenabled) {
	            \OCP\Util::writeLog('OC_useraafrapidconnect', 'qsacenabled so setting user with '.$username, \OCP\Util::DEBUG);
		    curl_close($ch);
		    if ($this->usermanager->userExists($username)) {
	            	\OCP\Util::writeLog('OC_useraafrapidconnect', 'username exists: '.$username, \OCP\Util::DEBUG);
		    }
	            else {
	            	\OCP\Util::writeLog('OC_useraafrapidconnect', 'username does not exist: '.$username, \OCP\Util::DEBUG);
		    }
		    $user = $this->usermanager->get($username);
		    if ($user === null) {
	            	\OCP\Util::writeLog('OC_useraafrapidconnect', 'username not found by usermanager for: '.$username, \OCP\Util::ERROR);
	                $parameters['internalexception'] = 'username not found by usermanager';
                        // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    	    	return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
		    }
		    else {
	            	\OCP\Util::writeLog('OC_useraafrapidconnect', 'username found by usermanager for:  '.$username, \OCP\Util::DEBUG);
			$this->session->set('user_id', $user->getUID());
			$this->activeuser = $user;
		        $this->usersession->setUser($user);
			if (!$this->usersession->isLoggedIn()) {
	            	     \OCP\Util::writeLog('OC_useraafrapidconnect', 'this usersession is not logged in', \OCP\Util::DEBUG);
			}
			else {
	            	     \OCP\Util::writeLog('OC_useraafrapidconnect', 'this usersession is logged in', \OCP\Util::DEBUG);
			}
			if ($user->isEnabled()) {
	            	        \OCP\Util::writeLog('OC_useraafrapidconnect', 'this user is enabled', \OCP\Util::DEBUG);
				$this->usersession->createSessionToken($this->request, $user->getUID(), $username, null);
				$this->session->set('last-password-confirm', time());
				$firstTimeLogin = $user->updateLastLoginTimeStamp();
				$userid = $user->getUID();
	            	        \OCP\Util::writeLog('OC_useraafrapidconnect', 'setupFS for user: '.$userid, \OCP\Util::DEBUG);
				OC_Util::setupFS($userid);
				if ($firstTimeLogin) {
					$userFolder = \OC::$server->getUserFolder($userid);
	            	        	\OCP\Util::writeLog('OC_useraafrapidconnect', 'in firstTimeLogin, user folder: '.$userFolder, \OCP\Util::DEBUG);
					\OC_Util::copySkeleton($userid, $userFolder);
//					\OC::$server->getEventDispatcher()->dispatch(IUser::class . '::firstLogin', new GenericEvent($user));
				}
	            	        // \OCP\Util::writeLog('OC_useraafrapidconnect', 'Login successful: '.$userid, \OCP\Util::INFO);
				// \OC_Hook::emit("OC_User", "post_login", array("uid" => $userid, 'password' => ''));
				return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/apps/files'));
			}
		    }
		}
		else {
		    curl_close($ch);
	            $parameters['qsacdisabled'] = 'QSAC not enabled';
                    // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
		}
	    }
        }
	else {
	    \OCP\Util::writeLog('OC_useraafrapidconnect', 'HTTP code is null', \OCP\Util::ERROR);
	    curl_close($ch);
	    $parameters['internalexception'] = 'HTTP code is null';
	    // return new TemplateResponse($this->appName, 'login', $parameters, 'guest');
	    return new Http\RedirectResponse($this->urlgenerator->getAbsoluteURL('/index.php/login'));
	}
    }

}
