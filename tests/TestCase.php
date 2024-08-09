<?php

namespace Dioroxic\Jwt\Tests;

use Dioroxic\Jwt\Jwt;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Orchestra\Testbench\TestCase as BaseTestCase;

class TestCase extends BaseTestCase
{
    protected User $userMock;

    protected function setUp(): void
    {
        parent::setUp();
        // 模拟\Illuminate\Foundation\Auth\User类
        $userMock = \Mockery::mock(User::class);
        // 模拟调用getKey方法返回1
        $userMock->shouldReceive('getKey')->andReturn(1);
        $this->userMock = $userMock;
    }

    protected function defineEnvironment($app)
    {
        tap($app['config'], function (Repository $config) {
            $config['jwt.secret'] = 'mock_secret';
            $config['jwt.expire'] = 3600;
        });
    }

    public function getTokenRequest()
    {
        $token = $this->getToekn();

        $request = Request::create('/foo', 'GET');
        $request->headers->set('Content-Type', 'application/json');
        $request->headers->set('Authorization', "Bearer {$token}");
        return $request;
    }

    public function getToekn()
    {
        return (new Jwt(\Illuminate\Http\Request::create('/foo', "GET")))->generate($this->userMock);
    }
}