<?php
namespace TaDaDa\Backend;

use Generator;
use TaDaDa\Auth;

interface Backend {
    public function __construct(mixed $resource, array $options);
    public function createBackendStructure():bool;
    public function getUrlByTokenId(string $token, string $id):false|string; /* find_url */
    public function getShareAuthentication (int $userid, string $urlid, int $sharetype = Auth::SHARE_PERMANENT):string;
    public function setAuthenticationConfirmed (string $authvalue):bool; /* confirm_auth */
    public function createAutentication (
        int $userid,
        string $authvalue,
        int $sharetype = Auth::SHARE_NONE,
        array $options = [],
        string $url = '',
        string $urlid = '',
        string $comment = '',
        int $duration = -1
    ):bool; /* add_auth */
    public function deleteAuthentication (string $authvalue):bool; /* del_auth */
    public function deleteAuthenticationById (int $id):bool;
    public function getAuthentication (string $authvalue):array|false;
    public function getAuthenticationById (int $id):array|false;
    public function updateAuthenticationDetails (string $authvalue, string $ip = '',  string $host ='' ):bool; /* refresh_auth */
    public function iterateAuthenticationByUserid (int $userid):Generator;
}