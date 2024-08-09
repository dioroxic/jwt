<?php

namespace Dioroxic\Jwt;

use Dioroxic\Jwt\Middleware\ApiAuth;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class JwtServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton('jwt', function () {
            return $this->app->make(Jwt::class);
        });
    }

    public function boot()
    {
        // 注册中间件
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('api.auth', ApiAuth::class);
        $this->publishes([
            __DIR__ . '/../config/jwt.php' => config_path('jwt.php'),
        ]);

        // 新增jwt看守器
        $this->app['auth']->extend('jwt', function ($app, $name, array $config) {
            $guard = new JwtGuard(
                $app['jwt'],
                $app['auth']->createUserProvider($config['provider']),
                $app['request']
            );

            // 将Request实例传入jwtGuard下的setRequest方法
            // $app->refresh('request', $guard, 'setRequest');
            return $guard;
        });
    }
}
