<?php

namespace Olayemiolaomo\ElasticLogger\Middleware;

use Closure;
use Olayemiolaomo\CapitalsageElasticLog\Logger;

class ElkLoggingMiddleware
{
    public function handle($request, Closure $next) {
        (new Logger())->log();

        return $next($request);
    }

}