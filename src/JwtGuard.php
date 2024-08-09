<?php

namespace Dioroxic\Jwt;

use BadMethodCallException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
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

    public function user(): ?Authenticatable
    {
        if ($this->user) {
            return $this->user;
        }

        if ($payload = $this->jwt->verify()) {
            return $this->user = $this->provider->retrieveById($payload->uid);
        }
        return null;
    }

    public function validate(array $credentials = []): bool
    {
        return (bool)$this->attempt($credentials, false);
    }

    /**
     * 尝试使用给定的凭据对用户进行身份验证，验证通过返回token
     * @param array $credentials
     * @param bool $login
     * @return bool|string
     * @throws \JsonException
     */
    public function attempt(array $credentials = [], bool $login = true)
    {
        $user = $this->provider->retrieveByCredentials($credentials);
        if ($user) {
            if ($login) {
                $this->setUser($user);
                return $this->jwt->generate($user);
            }
            return true;
        }

        return false;
    }

    public function __call($method, $parameters)
    {
        if (method_exists($this->jwt, $method)) {
            return call_user_func_array([$this->jwt, $method], $parameters);
        }

        if (static::hasMacro($method)) {
            return $this->macroCall($method, $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}