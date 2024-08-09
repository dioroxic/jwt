<?php

namespace Dioroxic\Jwt\Middleware;

use Dioroxic\Jwt\Exceptions\JwtException;
use Closure;
use Dioroxic\Jwt\Exceptions\UnauthorizedHttpException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class ApiAuth
{
    public function handle(Request $request, Closure $next)
    {
        try {
            if (!Auth::check()) {
                throw new UnauthorizedHttpException('Unauthorized', 401);
            }
        } catch (JwtException $exception) {
            throw new UnauthorizedHttpException('Unauthorized', 401);
        }

        return $next($request);
    }
}
