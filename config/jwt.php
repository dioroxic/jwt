<?php

return [
    'secret' => env('JWT_SECRET'),
    'expire' => env('JWT_EXPIRE', 3600),
];