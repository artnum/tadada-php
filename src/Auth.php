<?php
namespace TaDaDa;

use PDO;
use Exception;
use TaDaDa\Backend\Backend;

class Auth {
    protected $backend;
    protected $table;
    protected $timeout;
    protected $current_userid;

    const HASH = [
        'SHA-256' => ['sha256', 32],
        'SHA-384' => ['sha384', 48],
        'SHA-512' => ['sha512', 64]
    ];
    const SHARE_NONE =              0x00;
    const SHARE_TEMPORARY =         0x01;
    const SHARE_LIMITED_ONCE =      0x02; /* share until used once but with time limit */
    const SHARE_NOT_TIMED =         0x80; /* not used, below time apply, above time don't apply */
    const SHARE_PERMANENT =         0x81;
    const SHARE_PROXY =             0x82; /* to create token for proxy, never expires, not bound to any url, not bound to any user */
    const SHARE_UNLIMITED_ONCE =    0x83; /* share until used once */
    const SHARE_USER_PROXY =        0x84; /* to create token for proxy, never expires, not bound to any url, bound to specific user */

    function __construct(Backend $backend) {
        $this->backend = $backend;
        $this->timeout = 86400; // 24h
        $this->current_userid = -1;
    }

    function get_current_userid() {
        return $this->current_userid;
    }

    function find_url($token, $id) {
        return $this->backend->getUrlByTokenId($token, $id);
    }

    function generate_auth ($userid, $hpw, $cnonce = '', $hash = 'SHA-256') {
        $sign = random_bytes(Auth::HASH[$hash][1]);
        $authvalue = base64_encode(hash_hmac(Auth::HASH[$hash][0], $sign . $cnonce, base64_decode($hpw), true));
        if ($this->backend->createAutentication($userid, $authvalue)) {
            return base64_encode($sign);
        }
        return '';
    }

    function refresh_auth ($authvalue) {
        try {
            return $this->backend->updateAuthenticationDetails($authvalue);
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <refresh-auth>, "%s"', $e->getMessage()));
        }

    }

    function generate_share_auth ($userid, $authvalue, $url, $permanent = Auth::SHARE_PERMANENT, $comment = '', $duration = -1, $hash = 'SHA-256') {
        $urlid = sha1($url);
        $share_authvalue = $this->backend->getShareAuthentication($userid, $urlid, $permanent);
        if (!empty($share_authvalue)) { 
            $this->backend->updateAuthenticationDetails($share_authvalue);
            return $share_authvalue; 
        }
        $sign = random_bytes(Auth::HASH[$hash][1]);
        $share_authvalue = base64_encode(hash_hmac(Auth::HASH[$hash][0], $sign, base64_decode($authvalue), true));
        if ($this->add_auth($userid, $share_authvalue, $this->prepare_url($url), $permanent, $comment, $duration)) {
            return $share_authvalue;
        }
        return '';
    }

    function prepare_url_query($query) {
        $parts = explode('&', $query);
        $parts = array_filter($parts, function ($element) {
            /* access_token parameter is used to pass auth token, so it is not known when getting the shareable token */
            if (strpos($element, 'access_token=') === 0) { return false; }
            return true;
        });
        if (empty($parts)) { return ''; }
        /* sort to allow query begin like ?length=10&time=20 or ?time=20&length=10 */
        sort($parts, SORT_STRING);
        return '?' . implode('&', $parts);
    }

    function prepare_url($url) 
        /* we want tld and first level only. so sublevel can change without
         * invalidating url. protocols is not set as it must be https.
         */{
        $url = filter_var($url, FILTER_VALIDATE_URL);
        $parsed = parse_url($url);
        $host = [];
        $hostParts = explode('.', $parsed['host']);
        array_unshift($host, array_pop($hostParts));
        array_unshift($host, array_pop($hostParts));
        /* needed to allow hosts like localhost or any strange setup */
        $host = array_filter($host, function ($e) { return (empty($e) ? false : true); });
        $url = implode('.', $host);
        if (isset($parsed['path']) && $parsed['path'] !== null) {  $url .= str_replace('//', '/', $parsed['path']); }
        if (isset($parsed['query']) && $parsed['query'] !== null ) { $url .= $this->prepare_url_query($parsed['query']); }

        return str_replace('//', '/', $url);
    }

    function check_auth_header () {
        $url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
        try {
            $token = $this->get_auth_token();
        } catch (Exception $e) {
            return false;
        }
        return $this->check_auth($token, $url);
    }

    function confirm_auth ($authvalue) {
        try {
            return $this->backend->setAuthenticationConfirmed($authvalue);
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <confirm-auth>, "%s"', $e->getMessage()));
        }
    }

    function add_auth ($userid, $authvalue, $url = '', $sharetype = Auth::SHARE_NONE, $comment = '', $duration = -1) {
        $done = false;
        $ip = $_SERVER['REMOTE_ADDR'];
        $host = empty($_SERVER['REMOTE_HOST']) ? $ip : $_SERVER['REMOTE_HOST'];
        $ua = !empty($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

        if ($duration === -1) { $duration = $this->timeout; }
        $urlid = '';
        if ($sharetype !== Auth::SHARE_NONE) {
            $urlid = sha1($url);
        } else {
            $url = '';
        }
        try {
            $done = $this->backend->createAutentication(
                $userid,
                $authvalue,
                $sharetype,
                [
                    'ip' => $ip,
                    'host' => $host,
                    'ua' => $ua
                ],
                $url,
                $urlid,
                $comment,
                $duration
            );
        } catch (Exception $e) {
            error_log(sprintf('tadada-auth <add-auth>, "%s"', $e->getMessage()));
        } finally {
            return $done;
        }
    }

    function del_auth ($authvalue) {
        try {
            $this->backend->deleteAuthentication($authvalue);
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-auth>, "%s"', $e->getMessage()));
        }
        return true;
    }

    function check_auth ($authvalue, $url = '') {
        try {
            $urlid = '';
            if (!empty($url)) { $urlid = sha1($this->prepare_url($url)); }
            $auth = $this->backend->getAuthentication($authvalue);
            if ($auth === false) { return false; }
            
            if ((intval($auth['share']) < Auth::SHARE_NOT_TIMED)
                && (time() - intval($auth['time']) > intval($auth['duration']))
            ) {
                /* overtime, delete and next auth token ... if any */
                $this->del_all_connection_by_id($auth['uid']);                    
                return false;
            }             
            switch(intval($auth['share'])) {
                default:
                case Auth::SHARE_NOT_TIMED:
                    break;
                case Auth::SHARE_NONE:
                    $this->current_userid = intval($auth['userid']);
                    return true;
                case Auth::SHARE_PERMANENT:
                case Auth::SHARE_TEMPORARY:
                    if ($auth['urlid'] !== $urlid) { break; }
                    $this->current_userid = intval($auth['userid']);
                    return true;
                    break;
                case Auth::SHARE_PROXY: // proxy have complete access
                    $this->current_userid = 0;
                    return true;
                case Auth::SHARE_USER_PROXY:
                    $this->current_userid = intval($auth['userid']);
                    break;
                case Auth::SHARE_UNLIMITED_ONCE:
                case Auth::SHARE_LIMITED_ONCE:
                    $this->current_userid = intval($auth['userid']);
                    $this->del_all_connection_by_id($auth['uid']);
                    return true;
            }
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <check-auth>, "%s"', $e->getMessage()));
            return false;
        }
    }

    function get_id ($authvalue) {
        try {
            $auth = $this->backend->getAuthentication($authvalue);

            if ($auth === false) { return false; }
            if (
                (intval($auth['share']) !== Auth::SHARE_PERMANENT && intval($auth['share']) !== Auth::SHARE_PROXY) 
                && (time() - intval($auth['time']) > intval($auth['duration']))
            ) {
                $this->del_specific_auth($auth['auth']);
                return false;
            }

            return $auth['userid'];
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <get-id>, "%s"', $e->getMessage()));
        }
        return false;
    }

    function get_auth_token () {
        try {
            /* auth can be passed as url */
            if (!empty($_GET['access_token'])) {
                return $_GET['access_token'];
            }
            $authContent = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($authContent) !== 2) { throw new Exception(('Wrong auth header')); }
            return $authContent[1];
        } catch (Exception $e) {
            error_log(sprintf('tadada-auth <get-auth-token>, "%s"', $e->getMessage()));
        }
    }

    function get_active_connection ($userid) {
        $connections = [];
        try {
            while (($row = $this->backend->iterateAuthenticationByUserid($userid))) {
                if (time() - intVal($row['time'], 10) > $this->timeout) {
                    $this->backend->deleteAuthentication($row['auth']);
                } else {
                   $auth = '';
                   if (intval($row['share']) === Auth::SHARE_PERMANENT || intval($row['share']) === Auth::SHARE_TEMPORARY) {
                    $auth = $row['auth'];
                   }
                   $connections[] = [
                    'uid' => $row['uid'],
                    'time' => $row['time'],
                    'duration' => $row['duration'],
                    'useragent' => $row['useragent'],
                    'remoteip' => $row['remoteip'],
                    'remotehost' => $row['remotehost'],
                    'share' => $row['share'],
                    'url' => $row['url'],
                    'auth' => $auth,
                    'comment' => $row['comment']
                   ];
                }
            }
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <get-active-connection>, "%s"', $e->getMessage()));
        } finally {
            return $connections;
        }
    }

    function del_specific_auth ($authvalue) {
        try {
            $this->backend->deleteAuthentication($authvalue);
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-specific-auth>, "%s"', $e->getMessage()));
        }
    }            

    function del_specific_connection ($connectionid) {
        try {
            return $this->backend->deleteAuthenticationById($connectionid);
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-specific-connection>, "%s"', $e->getMessage()));
        } 
    }

    function del_all_shares ($userid) {
        try {
            while (($auth = $this->backend->iterateAuthenticationByUserid($userid))) {
                if ($auth['share'] !== self::SHARE_TEMPORARY 
                    && $auth['share'] !== self::SHARE_LIMITED_ONCE) { continue; }
                $this->backend->deleteAuthenticationById($auth['uid']);
            }
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-all-shares>, "%s"', $e->getMessage()));
        } 
    }

    function del_all_connections_shares ($userid) {
        try {
            while (($row = $this->backend->iterateAuthenticationByUserid($userid))) {
                $this->backend->deleteAuthenticationById($row['uid']);
            }
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-all-connections-shares>, "%s"', $e->getMessage()));
        }
        return true;
    }

    function del_all_connections ($userid) {
        try {
            while (($auth = $this->backend->iterateAuthenticationByUserid($userid))) {
                if ($auth['share'] !== self::SHARE_NONE) { continue; }
                $this->backend->deleteAuthenticationById($auth['uid']);
            }
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-all-connections>, "%s"', $e->getMessage()));
        } 
    }

    function get_auth_by_id ($uid) {
        try {
            return $this->backend->getAuthenticationById($uid);
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <get-auth-by-id>, "%s"', $e->getMessage()));
        }
    }

    function del_all_connection_by_id ($uid) {
        try {
            return $this->backend->deleteAuthenticationById($uid);
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-all-connection-by-id>, "%s"', $e->getMessage()));
        }
    }

    function get_authentication ($authvalue) {
        try {
            return $this->backend->getAuthentication($authvalue);
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <get-authentication>, "%s"', $e->getMessage()));
        }
    }
}