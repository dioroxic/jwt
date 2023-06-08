<?php

namespace AresEng\Jwt\Exceptions;

class JwtExpireException extends \Exception
{
    public function render()
    {
        return response()->json([
            'message' => $this->getMessage()
        ]);
    }
}