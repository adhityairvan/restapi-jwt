<?php

namespace App\Services\JWTAuth;
use App\Models\User;
use ReallySimpleJWT\Token;

/**
 * JWT Token class
 */
class JWTToken{
    public $secret;
    private $token;

    public function __construct($token)
    {
        $this->token = $token;
        $this->secret = env('JWT_SECRET', '123456');
    }

    /**
     * Getter function to get token
     *
     * @return void
     */
    public function getToken(){
        return $this->token;
    }

    /**
     * Static factory function to generate JWT Token using User instance
     *
     * @param User $user
     * @param integer $exp
     * @return void
     */
    public static function generate(User $user, $exp = 3600){
        $userId = $user->id;
        $secret = env('JWT_SECRET', '123456');
        $expiration = time() + $exp;
        $issuer = env('JWT_ISSUER', 'localhost');

        return new JWTToken(Token::create($userId, $secret, $expiration, $issuer));
    }

    /**
     * Validate JWT Token
     *
     * @return void
     */
    public function validate(){
        return Token::validate($this->token, $this->secret);
    }

    /**
     * Get payload from JWT Token
     *
     * @return Array
     */
    public function getPayload(){
        return Token::getPayload($this->token, $this->secret);
    }

}