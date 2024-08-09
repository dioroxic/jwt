<?php

namespace Dioroxic\Jwt\Facades;

use Illuminate\Support\Facades\Facade;

class Jwt extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'dioroxic.jwt';
    }
}