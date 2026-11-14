<?php
namespace App\Actions\Fortify;
use Laravel\Fortify\Http\Requests\LoginRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;

class AuthenticateUser
{
    public function invoke(LoginRequest $request)
    {
        $credentials = $request->only('email', 'password');
        $user = \App\Models\User::where('email', $credentials['email'])->first();
        if ($user) {
            $pepper = config('app.pepper');
            $passwordWithSaltAndPepper = $credentials['password'] . $user->salt . $pepper;
            if (Hash::check($passwordWithSaltAndPepper, $user->password)) {
                Auth::login($user);
                Log::info("User {$user->email} logged in successfully at " .now()."from ".$request->ip());
                return $user;
            
        }

        }
        return null;
    }
}
