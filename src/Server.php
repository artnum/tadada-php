<?php
namespace TaDaDa;

use PDO;
use Exception;
use TaDaDa\Auth;
use TaDaDa\User;
use TaDaDa\Backend\Backend;

class Server {
    const U_CONST_TIME = 100000;

    protected $auth;
    function __construct(Backend $backend) {
        $this->auth = new Auth($backend);
    }

    function usleep (float $time) {
        if ($time > 0) { return usleep((int)$time); }
        return;
    }

    function run (string $step, User $user) {        
        $start = microtime(true);
        try {
            header('Content-Type: application/json', true);
            if (empty($_SERVER['PATH_INFO'])) {
                throw new Exception();
            }
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                throw new Exception('Bad method');
            }
            $body = file_get_contents('php://input');
            $content = [];            
            if (!empty($body)) { $content = json_decode($body, true); }
            $output = [];

            switch ($step) {
                default: throw new Exception('Unknown step');
                case 'init':
                    $cnonce = null;
                    $hash = 'SHA-256';
                    if (!empty($content['hash']) && isset(Auth::HASH[$content['hash']])) {
                        $hash = $content['hash'];
                    }
                    if (!empty($content['cnonce'])) { $cnonce = base64_decode($content['cnonce']); }
                    if(empty($content['userid'])) { throw new Exception(); }
                    $data = $user->get($content['userid']);
                    if (!$data) {  throw new Exception();}
                    $auth = $this->auth->generate_auth($data['id'], $data['key'], $cnonce, $data['algo']);
                    if (empty($auth)) { throw new Exception(); }
                    $output = [
                        'auth' => $auth,
                        'count' => $data['key_iterations'],
                        'salt' => $data['key_salt'],
                        'userid' => intval($data['id']),
                        'algo' => $data['algo']
                    ];
                    break;
                case 'getshareable':
                    if (empty($content['url'])) { throw new Exception(); }
                case 'check':
                    $start = microtime(true);
                    if (empty($content['auth'])) { throw new Exception(); }
                    if (!$this->auth->confirm_auth($content['auth'])) { throw new Exception(); }
                    $this->auth->refresh_auth($content['auth']);
                    if ($step === 'getshareable') {
                        $hash = 'SHA-256';
                        if (!empty($content['hash']) && isset(Auth::HASH[$content['hash']])) {
                            $hash = $content['hash'];
                        }
                        $once = ((isset($content['once'])) ? ($content['once'] == true) : false);
                        $permanent = (isset($content['permanent']) ? ($content['permanent'] == true) : false);
                        $comment = (isset($content['comment']) ? htmlspecialchars(strval($content['comment'])) : '');
                        $duration = (isset($content['duration']) ? intval($content['duration']) : 86400);
                        $userid = $this->auth->get_current_userid();
                        $token = $this->auth->generate_share_auth(
                            $userid,
                            $content['auth'],
                            $content['url'], 
                            $once ? ($permanent ? Auth::SHARE_UNLIMITED_ONCE : Auth::SHARE_LIMITED_ONCE) 
                                  : ($permanent ? Auth::SHARE_PERMANENT : Auth::SHARE_TEMPORARY),
                            $comment,
                            $duration,
                            $hash
                        );
                        $this->auth->confirm_auth($token);
                        if (empty($token)) { throw new Exception(); }
                        $urlid = sha1($this->auth->prepare_url($content['url']));
                        $output = ['done' => true, 'token' => $token, 'duration' => $duration, 'urlid' => $urlid];
                        break;
                    }
                    $output = ['done' => true];
                    break;
                case 'quit':
                    if (empty($content['auth'])) { throw new Exception(); }
                    if (!$this->auth->del_auth($content['auth'])) { throw new Exception(); }
                    $output = ['done' => true];
                    break;
                case 'userid':
                    if (empty($content['username'])) { throw new Exception(); }
                    $data = $user->getByUsername($content['username']);
                    $output = ['userid' => $data['id']];
                    break;
                case 'active':
                    $token = $this->auth->get_auth_token();
                    if (!$this->auth->check_auth($token)) { throw new Exception(); }
                    $userid = $this->auth->get_id($token);
                    if (!$userid) { throw new Exception(); }
                    if (empty($content['userid'])) { throw new Exception(); }
                    if (
                        intval($content['userid']) !== intval($userid)
                        && !$user->canImpersonate($userid, $content['userid'])
                    ) { throw new Exception(); }
                    $connections = $this->auth->get_active_connection($content['userid']);
                    $output = ['userid' => intval($content['userid']), 'connections' => $connections];
                    break;
                case 'disconnect-all':
                case 'disconnect-share':
                case 'disconnect':
                    $token = $this->auth->get_auth_token();
                    if (!$this->auth->check_auth($token)) { throw new Exception(); }
                    $userid = $this->auth->get_id($token);
                    if (empty($content['userid'])) { throw new Exception(); }
                    if (
                        intval($content['userid']) !== intval($userid)
                        && !$user->canImpersonate($userid, $content['userid'])
                    ) { throw new Exception(); }
                    switch($step) {
                        case 'disconnect': 
                            if (!$this->auth->del_all_connections($content['userid'])) { throw new Exception(); } 
                            break;
                        case 'disconnect-all':
                            if (!$this->auth->del_all_connections_shares($content['userid'])) { throw new Exception(); }
                            break;
                        case 'disconnect-share':
                            if (!$this->auth->del_all_shares($content['userid'])) { throw new Exception(); }
                            break;
                    }
                    $output = ['userid' => intval($content['userid'])];
                    break;
                case 'disconnect-by-id':
                    $token = $this->auth->get_auth_token();
                    if (!$this->auth->check_auth($token)) { throw new Exception(); }
                    if (empty($content['uid'])) { throw new Exception(); }
                    $conn = $this->auth->get_auth_by_id($content['uid']);
                    if (!$conn) { throw new Exception(); }
                    $userid = $this->auth->get_id($token);
                    if (!$userid) { throw new Exception(); }
                    if (
                        intval($conn['userid']) !== intval($userid)
                        && !$user->canImpersonate($userid, $conn['userid'])
                    ) { throw new Exception(); }
                    $success = $this->auth->del_all_connection_by_id($conn['uid']);
                    $output = ['done' => $success];
                    break;
                case 'setpassword':
                    $token = $this->auth->get_auth_token();
                    if (!$this->auth->check_auth($token)) { throw new Exception(); }
                    $userid = $this->auth->get_id($token);
                    if (!$userid) { throw new Exception(); }
                    if (empty($content['userid'])) { throw new Exception(); }
                    if (empty($content['key'])) { throw new Exception(); }
                    if (empty($content['salt'])) { throw new Exception(); }
                    if (empty($content['iterations'])) { throw new Exception(); }
                    if (empty($content['algo'])) { throw new Exception(); }
                    if (
                        intval($content['userid']) !== intval($userid)
                        && !$user->canImpersonate($userid, $content['userid'])
                    ) { throw new Exception(); }
                    $user->setPassword($content['userid'], $content['key'],
                        ['key_algo' => $content['algo'], 
                        'key_iterations' => $content['iterations'],
                        'key_salt' => $content['salt']
                        ]
                    );
                    $output = ['userid' => intval($content['userid'])];
                    break;
                case 'whoami':
                    $token = $this->auth->get_auth_token();
                    if (!$this->auth->check_auth($token)) { throw new Exception(); }
                    $data = $this->auth->get_authentication($token);
                    if (!$data) { throw new Exception(); }
                    $output = ['userid' => intval($data['userid'])];
                    break;
            }
            $this->usleep($this::U_CONST_TIME - (microtime(true) + $start));
            echo json_encode($output);
        } catch (Exception $e) {
            $msg = $e->getMessage();
            $this->usleep($this::U_CONST_TIME - (microtime(true) + $start));
            if (!empty($msg)) { error_log($msg); }
            echo json_encode(['error' => 'Wrong parameter']); // not specific 
            exit(0);
        }
    }
}