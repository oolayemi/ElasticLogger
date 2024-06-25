<?php

namespace Olayemiolaomo\CapitalsageElasticLog;

use Carbon\Carbon;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Olayemiolaomo\CapitalsageElasticLog\Services\SensitiveDataMasker;

class Logger
{

    public $url;
    public $body;


    /**
     * @throws \Exception
     */
    public function __construct()
    {
        $this->url = $this->getUrl();
        $this->body = $this->postPayload();
    }

    public function log(): void
    {
        Http::post($this->url, $this->body);
    }

    /**
     * @throws \Exception
     */
    protected function getUrl(): string
    {
        $url = config('elk-logger.host') ?? env('ELK_LOGGER_URL');

        if ($url == null) {
            throw new \Exception("Please provide elastic log url", 500);
        }

        return $url;
    }

    /**
     * @throws \Exception
     */
    protected function postPayload(): array
    {
        try {
            $sensitiveDataMasker = new SensitiveDataMasker();
            $request = request();

            $API_LOGGER_CONTENT_TYPES = [
                "application/json",
                "application/vnd.api+json",
                "application/gzip",
                "application/octet-stream",
            ];

            $responseBody = null;

            if (in_array($request->getContentType(), $API_LOGGER_CONTENT_TYPES)) {
                if ($request->getContentType() == "application/gzip") {
                    $responseBody = '** GZIP Archive **';
                } elseif ($request->getContentType() == "application/octet-stream") {
                    $responseBody = '** Binary File **';
                } elseif ($request->streaming ?? false) {
                    $responseBody = '** Streaming **';
                }
            }


            $startTime = microtime(true);

            $user = $request->user();

            return [
                'environment' => config('app.env'),
                'user_id' => $user != null ? $user->id ?? null : null,
                'email' => $user != null ? $user->email ?? null : null,
                'added_on' => Carbon::now(),
                'execution_time' => Carbon::now()->diffInSeconds(Date::parse($startTime)),
                'response' => $sensitiveDataMasker->maskSensitiveData($responseBody),
                'client_ip_address' => $request->ip() ?? null,
                'method' => $request->method() ?? null,
                'body' => $sensitiveDataMasker->maskSensitiveData($request->getContent() != null
                    ? $request->getContent() ?? null
                    : null),
                'headers' => $sensitiveDataMasker->maskSensitiveData($request->headers != null
                    ? $request->headers->all()
                    : null),
                'api' => $sensitiveDataMasker->maskSensitiveData($request->getQueryString(), true)
            ];
        } catch (\Exception $exception) {
            throw new \Exception($exception->getMessage(), 500);
        }
    }

}