<?php

namespace AresEng\Jwt;

use AresEng\Jwt\Exceptions\JwtExpireException;
use AresEng\Jwt\Exceptions\JwtSecretException;
use AresEng\Jwt\Exceptions\JwtTokenException;
use Illuminate\Foundation\Auth\User;

class Jwt
{
    private $secret;

    public function __construct()
    {
        $this->secret = env('JWT_SECRET');
        if (!$this->secret) {
            throw new JwtSecretException('jwt secret cannot be null');
        }
    }

    // 生成token
    public function generate(User $user): string
    {
        $jwtHeader = base64_encode(json_encode([
            "typ" => "JWT",
            "alg" => "HS256"
        ]));

        $jwtPayload = base64_encode(json_encode([
            "exp" => now()->timestamp + 3600,
            "uid" => $user->getKey()
        ]));

        $base64String = $jwtHeader . $jwtPayload;
        $jwtSecret    = hash_hmac('sha256', $base64String, $this->secret);
        return "{$jwtHeader}.{$jwtPayload}.{$jwtSecret}";
    }

    // 验证token
    public function verify($token)
    {
        $tokenArr = explode('.', $token);
        if (count($tokenArr) < 3) {
            throw new JwtTokenException("Unauthorized");
        }
        [$header, $payload,] = explode('.', $token);
        $signature   = hash_hmac("sha256", $header . $payload, $this->secret);
        $verifyToken = "{$header}.{$payload}.{$signature}";
        if ($verifyToken != $token) {
            throw new JwtSecretException("jwt verification error");
        }

        $payload = json_decode(base64_decode($payload));
        if (now()->timestamp >= $payload->exp) {
            throw new JwtExpireException("jwt expiration");
        }
        return $payload;
    }
}