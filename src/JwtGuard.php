<?php

namespace AresEng\Jwt;

use AresEng\Jwt\Exceptions\JwtTokenException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;

class JwtGuard implements Guard
{
    use GuardHelpers, Macroable {
        __call as macroCall;
    }

    protected Jwt $jwt;
    protected Request $request;

    public function __construct(Jwt $jwt, UserProvider $userProvider, Request $request)
    {
        $this->provider = $userProvider;
        $this->jwt      = $jwt;
        $this->request  = $request;
    }

    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        $token = $this->getToken();
        if ($token && $payload = $this->jwt->verify($token)) {
            return $this->user = $this->provider->retrieveById($payload->uid);
        }
    }

    public function getToken()
    {
        $authorizationHeader = $this->request->header('Authorization');
        if ($authorizationHeader) {
            $tokenArr = explode(' ', $authorizationHeader);
            if (count($tokenArr) >= 2 && isset($tokenArr[1])) {
                [, $token] = $tokenArr;
                return $token;
            }
        }
    }

    public function validate(array $credentials = [])
    {
        return (bool)$this->attempt($credentials, false);
    }

    public function attempt(array $credentials = [], $login = true)
    {
        $user = $this->provider->retrieveByCredentials($credentials);
        if ($this->hasValidCredentials($user, $credentials)) {
            return $login ? $this->login($user) : true;
        }

        return false;
    }

    public function login(User $user)
    {
        return $this->jwt->generate($user);
    }

    protected function hasValidCredentials($user, $credentials)
    {
        return $user !== null && $this->provider->validateCredentials($user, $credentials);
    }

    public function __call($method, $parameters)
    {
        if (method_exists($this->jwt, $method)) {
            return call_user_func_array([$this->jwt, $method], $parameters);
        }

        if (static::hasMacro($method)) {
            return $this->macroCall($method, $parameters);
        }

        throw new \BadMethodCallException("Method [$method] does not exist.");
    }
}