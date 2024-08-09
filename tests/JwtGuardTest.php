<?php

namespace Dioroxic\Jwt\Tests;

use Dioroxic\Jwt\Jwt;
use Dioroxic\Jwt\JwtGuard;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Mockery;

class JwtGuardTest extends TestCase
{
    protected JwtGuard $jwtGuard;

    protected function setUp(): void
    {
        parent::setUp();

        $eloquentUserProviderMock = Mockery::mock(EloquentUserProvider::class);
        $eloquentUserProviderMock->shouldReceive('retrieveByCredentials')->with(['email' => 'test@example.com', 'password' => 'password'])->andReturn($this->userMock);
        $eloquentUserProviderMock->shouldReceive('retrieveByCredentials')->with(['email' => 'errortest@example.com', 'password' => 'password'])->andReturn(false);
        $eloquentUserProviderMock->shouldReceive('retrieveById')->with(1)->andReturn($this->userMock);

        $this->jwtGuard = new JwtGuard(
            new Jwt($this->getTokenRequest()),
            $eloquentUserProviderMock,
            $this->app['request']
        );
    }

    public function testAttemptReturnToken()
    {
        $result = $this->jwtGuard->attempt(['email' => 'test@example.com', 'password' => 'password'], true);
        $this->assertStringMatchesFormat("%s.%s.%s", $result);
    }

    public function testAttemptReturnTrue()
    {
        $result = $this->jwtGuard->attempt(['email' => 'test@example.com', 'password' => 'password'], false);
        $this->assertTrue($result);
    }

    public function testAttemptReturnFalse()
    {
        $result = $this->jwtGuard->attempt(['email' => 'errortest@example.com', 'password' => 'password'], false);
        $this->assertNotTrue($result);
    }

    public function testValidateReturnTrue()
    {
        $result = $this->jwtGuard->validate(['email' => 'test@example.com', 'password' => 'password']);
        $this->assertTrue($result);
    }

    public function testValidateReturnFalse()
    {
        $result = $this->jwtGuard->validate(['email' => 'errortest@example.com', 'password' => 'password']);
        $this->assertNotTrue($result);
    }

    public function testUserReturnUser()
    {
        $this->jwtGuard->setUser($this->userMock);

        $user = $this->jwtGuard->user();
        $this->assertInstanceOf(User::class, $user);
    }

    public function testUserByTokenReturnUser()
    {
        $user = $this->jwtGuard->user();
        $this->assertInstanceOf(User::class, $user);
    }
}
