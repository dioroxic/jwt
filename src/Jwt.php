<?php

namespace Dioroxic\Jwt;

use Dioroxic\Jwt\Exceptions\JwtException;
use Dioroxic\Jwt\Exceptions\TokenInvalidException;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;

class Jwt
{
    private $secret;
    private $expire;

    protected Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
        $this->secret  = config('jwt.secret');
        $this->expire  = config('jwt.expire');
        if (!$this->secret) {
            throw new JwtException('Jwt secret cannot be null');
        }
    }

    // 生成token
    public function generate(User $user): string
    {
        $jwtHeader = base64_encode(json_encode([
            "typ" => "JWT",
            "alg" => "HS256"
        ], JSON_THROW_ON_ERROR));

        $jwtPayload = base64_encode(json_encode([
            "exp" => now()->timestamp + $this->expire,
            "uid" => $user->getKey()
        ], JSON_THROW_ON_ERROR));

        $base64String = $jwtHeader . $jwtPayload;
        $jwtSecret    = hash_hmac('sha256', $base64String, $this->secret);
        return "{$jwtHeader}.{$jwtPayload}.{$jwtSecret}";
    }

    /**
     * 验证token
     * @return mixed|void
     * @throws TokenInvalidException
     * @throws \JsonException
     */
    public function verify()
    {
        $token    = $this->request->bearerToken();
        $tokenArr = explode('.', $token);
        if (empty($token)) {
            throw new TokenInvalidException("Empty token");
        }
        if (count($tokenArr) !== 3) {
            throw new TokenInvalidException("Invalid token");
        }
        [$header, $payload,] = $tokenArr;
        $signature   = hash_hmac("sha256", $header . $payload, $this->secret);
        $verifyToken = "{$header}.{$payload}.{$signature}";
        if ($verifyToken !== $token) {
            throw new TokenInvalidException("Token verification error");
        }

        $payload = json_decode(base64_decode($payload), false, 512, JSON_THROW_ON_ERROR);
        if (now()->timestamp <= $payload->exp) {
            return $payload;
        }
    }
}