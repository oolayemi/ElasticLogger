<?php

namespace Olayemiolaomo\CapitalsageElasticLog\Services;
class SensitiveDataMasker
{
    // Here you define the sensitive keys that need to be masked
    protected $sensitiveKeys = ['password', 'api_key', 'token', 'access', 'refresh']; // Add other keys as needed

    /**
     * Masks sensitive data in the provided input.
     *
     * @param mixed $data The data to be processed, can be a string, array, or URL.
     * @param bool $maskApiParameters Whether to mask sensitive parameters in a URL string.
     * @return mixed The processed data with sensitive information masked.
     */
    public function maskSensitiveData($data, $maskApiParameters = true)
    {
        if (is_string($data) && $maskApiParameters) {
            foreach ($this->sensitiveKeys as $sensitiveKey) {
                $pattern = '/(' . preg_quote($sensitiveKey) . '=)(.*?)(?=(&|$))/';
                $data = preg_replace($pattern, '\1***FILTERED***', $data);
            }
            return $data;
        }

        if (is_array($data)) {
            foreach ($data as $key => $value) {
                if (in_array($key, $this->sensitiveKeys)) {
                    $data[$key] = '***FILTERED***';
                } elseif (is_array($value) || is_object($value)) {
                    $data[$key] = $this->maskSensitiveData($value, $maskApiParameters);
                }
            }
            return $data;
        }

        if (is_object($data)) {
            foreach ($data as $key => $value) {
                if (in_array($key, $this->sensitiveKeys)) {
                    $data->$key = '***FILTERED***';
                } elseif (is_array($value) || is_object($value)) {
                    $data->$key = $this->maskSensitiveData($value, $maskApiParameters);
                }
            }
            return $data;
        }

        return $data;
    }
}
