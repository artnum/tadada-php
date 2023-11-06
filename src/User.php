<?php
namespace TaDaDa;

interface User {
    public function get($userid):int;
    public function getByUsername($username):int;
    public function setPassword($userid, $key, $keyopts);
    public function canImpersonate($userid, $impersonateid):bool;
}