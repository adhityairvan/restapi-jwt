<?php

namespace App\Services\JWTAuth;

use App\Models\User;
use Illuminate\Contracts\Auth\Guard;
use App\Services\JWTAuth\JWTToken;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;

/**
 * Custom guard class for our JWT Auth
 */
class JWTGuard implements Guard{
    /**
     * User Model
     *
     * @var App\Models\User
     */
    private $user;
    public $provider, $request, $storage, $token;

    public function __construct(JWTStorage $storage, UserProvider $userProvider, Request $request)
    {
        $this->provider = $userProvider;
        $this->storage = $storage;
        $this->request = $request; 
    }

    /**
     * Validate username and password to login
     *
     * @param array $credentials
     * @return void
     */
    public function validate(array $credentials = [])
    {
        $user = User::where(['email' => $credentials['email']])->first();
        if(Hash::check($credentials['password'], $user->password)){
            $this->user = $user;
            $this->storage->storeToken($user->id, JWTToken::generate($user)->getToken());
            return true;
        }
        return false;
    }

    /**
     * Get user account associated with JWT Token
     *
     * @return void
     */
    public function user()
    {
        if($this->user != null){
            return $this->user;
        }
        else if($this->request->hasHeader('Authorization')){
            $token =  explode(' ', $this->request->header('Authorization'))[1];
            $jwt = new JWTToken($token);
            if($jwt->validate()){
                $this->user = User::find($jwt->getPayload()['user_id']);
                $this->token = $jwt->getToken();
                return $this->user;
            }
        }
    }

    /**
     * Check wether user is authenticated or not
     *
     * @return void
     */
    public function check(){
        $this->user();
        if($this->user) return true;
        return false;
    }

    /**
     * Get logged in user id
     *
     * @return void
     */
    public function id()
    {
        if($this->check()) return $this->user->id;
        return null;
    }

    /**
     * Check guest status 
     *
     * @return void
     */
    public function guest()
    {
        if($this->check()) return false;
        return true;
    }

    /**
     * login the user using user model instance
     *
     * @param Authenticatable $user
     * @return String
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
        $token = $user->getUserToken();
        $this->storage->storeToken($user->id, $token);
        return $token;
    }

    public function logout(){
        $this->storage->deleteToken($this->user->id);
        return;
    }
    

}