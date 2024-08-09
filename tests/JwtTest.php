<?php

namespace Dioroxic\Jwt\Tests;

use Dioroxic\Jwt\Exceptions\JwtException;
use Dioroxic\Jwt\Exceptions\TokenExpireException;
use Dioroxic\Jwt\Exceptions\TokenInvalidException;
use Dioroxic\Jwt\Jwt;
use Illuminate\Http\Request;

class JwtTest extends TestCase
{
    public function testNullSecret()
    {
        $this->app['config']->set('jwt.secret', '');

        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Jwt secret cannot be null');

        new Jwt(Request::create('/foo', 'GET'));
    }
    
    public function testGenerate()
    {
        $token = $this->getToekn();
        $this->assertStringMatchesFormat("%s.%s.%s", $token);
    }

    public function testVerifyWithEmptyToekn()
    {
        $request = Request::create('/foo', 'GET');
        $request->headers->set('Content-Type', 'application/json');
        $jwt = new Jwt($request);

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Empty token');
        $jwt->verify();
    }

    public function testVerifyWithInvalidToken()
    {
        $request = Request::create('/foo', 'GET');
        $request->headers->set('Content-Type', 'application/json');
        $request->headers->set('Authorization', 'Bearer foo');
        $jwt = new Jwt($request);

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Invalid token');

        $jwt->verify();
    }

    public function testVerifyWithErrorToken()
    {
        $request = Request::create('/foo', 'GET');
        $request->headers->set('Content-Type', 'application/json');
        $request->headers->set('Authorization', 'Bearer mock.mock.mock');

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token verification error');

        $jwt = new Jwt($request);
        $jwt->verify();
    }

    public function testVerify()
    {
        $jwt      = new Jwt($this->getTokenRequest());
        $payload  = $jwt->verify();

        $this->assertIsObject($payload);
        $this->assertObjectHasProperty('exp', $payload);
        $this->assertObjectHasProperty('uid', $payload);
    }
}
