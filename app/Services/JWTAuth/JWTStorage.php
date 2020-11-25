<?php

namespace App\Services\JWTAuth;

use Illuminate\Support\Facades\Cache;

/**
 * Class to handle interaction on laravel cache
 */
class JWTStorage{
    public $tags = 'jwt';

    /**
     * Store token with associated user id
     *
     * @param Integer $userId
     * @param String $token
     * @return void
     */
    public function storeToken($userId, $token){
        Cache::tags($this->tags)->put('user_'.$userId,$token);
    }

    /**
     * Get token for user id on cache
     *
     * @param Integer $userId
     * @return void
     */
    public function getToken($userId){
        $token = Cache::tags($this->tags)->get('user_'.$userId);
        return $token;
    }

    public function deleteToken($userId){
        Cache::tags($this->tags)->delete('user_'.$userId);
    }

}