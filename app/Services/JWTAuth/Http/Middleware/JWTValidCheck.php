<?php

namespace App\Services\JWTAuth\Http\Middleware;

use Closure;
use App\Services\JWTAuth\JWTStorage;

/**
 * Middleware class to reject blacklisted token
 */
class JWTValidCheck{
    public $storage;

    public function __construct(JWTStorage $storage)
    {
        $this->storage = $storage;    
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $token = $this->storage->getToken($request->user()->id);
        if(!$token){
            return response()->json([
                'status' => 'ERROR',
                'message' => 'Expire/Invalid Token'
            ]);
        }
        // We reject the token if we dont have it on cache (that means token is expired or already deleted)
        $requestToken = explode(' ', $request->header('Authorization'))[1];
        if($requestToken == $token){
            return $next($request);
        }
        return response()->json([
            'status' => 'ERROR',
            'message' => 'Expire/Invalid Token'
        ]);
    }
}