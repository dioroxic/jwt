<?php

namespace AresEng\Jwt\Exceptions;

class JwtSecretException extends \Exception
{
    public function render()
    {
        return response()->json([
            'message' => $this->getMessage()
        ]);
    }
}