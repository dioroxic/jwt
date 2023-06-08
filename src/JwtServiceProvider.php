<?php

namespace AresEng\Jwt;

use AresEng\Jwt\Middleware\ApiAuth;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class JwtServiceProvider extends ServiceProvider
{
    protected $defer = true;

    public function register()
    {
        $this->app->singleton('ares.jwt', function () {
            return new Jwt();
        });
    }

    public function boot()
    {
        // 注册中间件
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('api.auth', ApiAuth::class);

        // 新增jwt guard
        $this->app['auth']->extend('jwt', function ($app, $name, array $config) {
            $guard = new JwtGuard(
                $app['ares.jwt'],
                $app['auth']->createUserProvider($config['provider']),
                $app['request']
            );

            $app->refresh('request', $guard, 'setRequest');
            return $guard;
        });
    }
}