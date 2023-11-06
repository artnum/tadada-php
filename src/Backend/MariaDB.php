<?php
namespace TaDaDa\Backend;

use PDO;
use Generator;
use TaDaDa\Auth;

class MariaDB implements Backend {
    const DEFAULT_TABLE_NAME = 'tadada_auth';
    protected $pdo;
    protected $table;

    function __construct(PDO $pdo, array $parameters = ['table' => self::DEFAULT_TABLE_NAME]) {
        $this->pdo = $pdo;
        if (!isset($parameters['table']) 
            || empty($parameters['table'])
            || $parameters['table'] === null) { $parameters['table'] = self::DEFAULT_TABLE_NAME; }
        $this->table = $parameters['table'];
    }

    public function createBackendStructure ():bool 
    {
        $stmt = $this->pdo->prepare(sprintf(<<<'EOQ'
                CREATE TABLE IF NOT EXISTS %s (
                    uid         INTEGER UNSIGNED    PRIMARY KEY AUTO_INCREMENT,
                    auth        CHAR(255)           NOT NULL,
                    userid      INTEGER UNSIGNED    NOT NULL,
                    time        INTEGER UNSIGNED    NOT NULL DEFAULT 0,
                    started     INTEGER UNSIGNED    NOT NULL DEFAULT 0,
                    duration    INTEGER UNSIGNED    NOT NULL default 0,
                    confirmed   INTEGER(1) UNSIGNED NOT NULL DEFAULT 0,
                    remotehost  VARCHAR(256)        NOT NULL DEFAULT '',
                    remoteip    VARCHAR(40)         NOT NULL DEFAULT '',
                    useragent   VARCHAR(100)        NOT NULL DEFAULT '',
                    share       INT(1) UNSIGNED     NOT NULL DEFAULT 0,
                    urlid       CHAR(40)            NOT NULL DEFAULT '',
                    url         TEXT                NOT NULL DEFAULT '',
                    comment     CHAR(140)           NOT NULL DEFAULT '',

                    INDEX (auth, userid, urlid),
                    UNIQUE(auth)
                )
            EOQ, $this->table)
        );
        return $stmt->execute();
    }

    public function getUrlByTokenId(string $token, string $id):string|false 
    {
        $stmt = $this->pdo->prepare(
            sprintf('SELECT url FROM %s WHERE auth = :token AND urlid = :urlid', $this->table)
        );
        $stmt->bindValue(':urlid', $id, PDO::PARAM_STR);
        $stmt->bindValue(':token', $token, PDO::PARAM_STR);

        if(!$stmt->execute()) { return false; }
        $row = $stmt->fetch();
        if (!$row || empty($row)) { return false; }
        return $row['url'];
    }

    public function getShareAuthentication (int $userid, string $urlid, int $sharetype = Auth::SHARE_PERMANENT):string
    {
        $stmt = $this->pdo->prepare(
            sprintf('SELECT auth FROM %s WHERE userid = :userid AND urlid = :urlid AND share = :share', $this->table)
        );
        $stmt->bindValue(':userid', $userid, PDO::PARAM_INT);
        $stmt->bindValue(':urlid', $urlid, PDO::PARAM_STR);
        $stmt->bindValue(':share', $sharetype, PDO::PARAM_INT);
        $result = $stmt->execute();
        if (!$result) { return ''; }
        if ($stmt->rowCount() !== 1) { return ''; }
        return $stmt->fetch(PDO::FETCH_ASSOC)['auth'];
    }

    public function setAuthenticationConfirmed (string $authvalue):bool
    {
        $stmt = $this->pdo->prepare(
            sprintf('UPDATE %s SET "time" = :time, "confirmed" = 1 WHERE auth = :auth', $this->table)
        );
        $stmt->bindValue(':auth', $authvalue, PDO::PARAM_STR);
        $stmt->bindValue(':time', time(), PDO::PARAM_INT);
        return $stmt->execute();
    }

    public function createAutentication (
        int $userid,
        string $authvalue,
        int $sharetype = Auth::SHARE_NONE,
        array $options = [],
        string $url = '',
        string $urlid = '',
        string $comment = '',
        int $duration = -1
    ):bool
    {
        $ip = !empty($options['ip']) ? $options['ip'] : '';
        $host = !empty($options['host']) ? $options['host'] : $ip;
        $ua = !empty($options['ua']) ? $options['ua'] : '';

        $stmt = $this->pdo->prepare(
            sprintf('INSERT INTO %s 
                (
                    userid,
                    auth,
                    started,
                    duration,
                    remotehost,
                    remoteip,
                    useragent,
                    share,
                    urlid,
                    url, 
                    comment
                ) VALUES (
                    :uid,
                    :auth,
                    :started,
                    :duration,
                    :remotehost,
                    :remoteip,
                    :useragent,
                    :share,
                    :urlid,
                    :url,
                    :comment
                );', $this->table)
        );
        $stmt->bindValue(':uid', $userid, PDO::PARAM_STR);
        $stmt->bindValue(':auth', $authvalue, PDO::PARAM_STR);
        $stmt->bindValue(':started', time(), PDO::PARAM_INT);
        $stmt->bindValue(':duration', $duration, PDO::PARAM_INT);
        $stmt->bindValue(':remotehost', $host, PDO::PARAM_STR);
        $stmt->bindValue(':remoteip', $ip, PDO::PARAM_STR);
        $stmt->bindValue(':useragent', $ua, PDO::PARAM_STR);
        $stmt->bindValue(':share', $sharetype, PDO::PARAM_INT);
        $stmt->bindValue(':urlid', $urlid, PDO::PARAM_STR);
        $stmt->bindValue(':url', $url, PDO::PARAM_STR);
        $stmt->bindValue(':comment', substr($comment, 0, 140), PDO::PARAM_STR);
        return $stmt->execute();
    }

    public function deleteAuthentication (string $authvalue):bool
    {
        $stmt = $this->pdo->prepare(
            sprintf('DELETE FROM %s WHERE auth = :auth', $this->table)
        );
        $stmt->bindValue(':auth', $authvalue, PDO::PARAM_STR);
        return $stmt->execute();
    }

    public function getAuthentication (string $authvalue):array|false
    {
        $stmt = $this->pdo->prepare(
            sprintf('SELECT * FROM %s WHERE auth = :auth', $this->table)
        );
        $stmt->bindValue(':auth', $authvalue, PDO::PARAM_STR);
        $stmt->execute();
        if ($stmt->rowCount() !== 1) { return false; }
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function updateAuthenticationDetails (string $authvalue, string $ip = '',  string $host ='' ):bool
    {
        $time = time();
        $stmt = $this->pdo->prepare(
            sprintf('UPDATE %s SET time = :time, remotehost = :remotehost, remoteip = :remoteip WHERE auth = :auth', $this->table)
        );
        $stmt->bindValue(':auth', $authvalue, PDO::PARAM_STR);
        $stmt->bindValue(':time', $time, PDO::PARAM_INT);
        $stmt->bindValue(':remotehost', $host, PDO::PARAM_STR);
        $stmt->bindValue(':remoteip', $ip, PDO::PARAM_STR);
        return $stmt->execute();
    }

    public function iterateAuthenticationByUserid (int $userid):Generator
    {
        $stmt = $this->pdo->prepare(
            sprintf('SELECT * FROM %s WHERE userid = :userid', $this->table)
        );
        $stmt->bindValue(':userid', $userid, PDO::PARAM_INT);
        $stmt->execute();
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC))) {
            yield $row;
        }
    }

    public function deleteAuthenticationById (int $id):bool
    {
        $stmt = $this->pdo->prepare(sprintf('DELETE FROM %s WHERE uid = :uid', $this->table));
        $stmt->bindValue(':uid', $id, PDO::PARAM_INT);
        return $stmt->execute();
    }

    public function getAuthenticationById (int $id):array|false 
    {
        $stmt = $this->pdo->prepare(sprintf('SELECT * FROM %s WHERE uid = :uid', $this->table));
        $stmt->bindValue(':uid', $id, PDO::PARAM_INT);
        if (!$stmt->execute()) { return false; }
        if ($stmt->rowCount() !== 1) { return false; }
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
}