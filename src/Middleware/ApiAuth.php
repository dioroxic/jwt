<?php

namespace AresEng\Jwt\Middleware;

use AresEng\Jwt\Exceptions\JwtTokenException;
use Closure;
use Illuminate\Http\Request;

class ApiAuth
{
    public function handle(Request $request, Closure $next)
    {
        $authorizationHeader = $request->header('Authorization');
        if (!$authorizationHeader) {
            throw new JwtTokenException('Unauthorized', 401);
        }
        $tokenArr = explode(' ', $authorizationHeader);
        if (count($tokenArr) < 2 || !isset($tokenArr[1])) {
            throw new JwtTokenException('Unauthorized', 401);
        }

        [, $token] = $tokenArr;
        $request->token = $token;
        return $next($request);
    }
}
