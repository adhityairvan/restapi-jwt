<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    /**
     * we need to set default middleware (Auth middleware with api guard)
     * 
     */
    public function __construct()
    {
        // guard all function except login
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
        $this->middleware('jwt_valid', ['except' => ['login', 'register']]);
    }

    /**
     * login functionality
     *
     * @param Request $request
     * @return void
     */
    public function login(Request $request){
        // always validate before processing the request
        $credential = $request->validate([
            'email' => 'required|email',
            'password' => 'required|alpha_num|min:6'
        ]);
        
        // attempt to login with user provided credential
        // if we dont get any token, that means user provided wrong credentials
        if(!Auth::validate($credential)){
            return response()->json([
                'status' => 'ERROR',
                'message' => 'Unauthorized. Wrong credentials'
            ], 401);
        }
        

        return $this->tokenResponse(auth()->user()->getUserToken());
    }

    /**
     * function to logout user and delete JWT token
     *
     * @param Request $request
     * @return void
     */
    public function logout(Request $request){
        // blacklist the token
        auth()->logout();
        return response()->json([
            'status' => 'OK',
            'message' => 'Logout successful'
        ]);
    }

    /**
     * Register functionality
     *
     * @param Request $request
     * @return void
     */
    public function register(Request $request){
        // validate incoming request
        try{
            $cleaned = $request->validate([
                'name' => 'required|string|max:255',
                'email' => 'required|email|unique:users',
                'password' => 'required|string|alpha_num|min:6|confirmed'
            ]);
        }catch(ValidationException $e){
            // return error message to user
            return $e->errors();
        }

        // create new user, dont forget to hash the plain password
        $user = User::create([
            'name' => $cleaned['name'],
            'email' => $cleaned['email'],
            'password' => bcrypt($cleaned['password'])
        ]);

        // need to generate token and return it to user
        auth()->setUser($user);
        
        return $this->tokenResponse(auth()->user()->getUserToken());
    }

    /**
     * refresh user token
     *
     * @param Request $request
     * @return void
     */
    public function refresh(Request $request){
        return $this->tokenResponse(auth()->refresh());
    }

    /**
     * function to get info about logged in user
     *
     * @param Request $request
     * @return void
     */
    public function user(Request $request){
        return $request->user();
    }

    protected function tokenResponse(String $token){
        return response()->json([
            'status' => 'OK',
            'token' => $token,
        ]);
    }
}
