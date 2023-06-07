<?php

namespace App\Http\Controllers\api;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\StoreUserRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    
    //register users with token
    public function register (StoreUserRequest $request)
    {
        $request->validated($request->only(['name', 'email', 'password']));

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);
        return response()->json([
            'msg'=>'done' ,
            'user'=>$user,
            'token'=>$user->createToken('api token for user'.$user->name)->plainTextToken
        ],201);
        
    }

    // login xd 
    public function login(LoginRequest $request) 
    {
        $request->validated($request->only(['email', 'password']));

        if(!Auth::attempt($request->only(['email', 'password']))) {
            return $this->error('', 'Credentials do not match', 401);
        }

        $user = User::where('email', $request->email)->first();

        return response()->json([
            'msg'=>'done' ,
            'user'=>$user,
            'token'=>$user->createToken('api token for user'.$user->name)->plainTextToken
        ],201);
    }
    public function logout() 
    {
        Auth::user()->currentAccessToken()->delete();
        return response()->json([
            'msg'=>'done' ,
            
        ],200);
    }
    public function nothing () 
    {
        return $this->format() ;
    }
}
