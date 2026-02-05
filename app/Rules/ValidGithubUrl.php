<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Facades\Log;

class ValidGithubUrl implements ValidationRule
{
    /**
     * Run the validation rule.
     *
     * Validates that a URL is a safe GitHub API or HTML URL,
     * preventing SSRF attacks by blocking internal hosts and private IP ranges.
     */
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (empty($value)) {
            return;
        }

        if (! is_string($value)) {
            $fail('The :attribute must be a string.');

            return;
        }

        // Must be a valid URL
        if (! filter_var($value, FILTER_VALIDATE_URL)) {
            $fail('The :attribute must be a valid URL.');

            return;
        }

        $parsed = parse_url($value);

        // Must use HTTPS
        $scheme = strtolower($parsed['scheme'] ?? '');
        if ($scheme !== 'https') {
            $fail('The :attribute must use HTTPS.');

            return;
        }

        // Must have a host
        $host = strtolower($parsed['host'] ?? '');
        if (empty($host)) {
            $fail('The :attribute must contain a valid host.');

            return;
        }

        // Block localhost and internal hostnames
        $internalHosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
        if (in_array($host, $internalHosts) || str_ends_with($host, '.local')) {
            Log::warning('GitHub URL validation failed - internal host', [
                'url' => $value,
                'host' => $host,
                'ip' => request()->ip(),
                'user_id' => auth()->id(),
            ]);
            $fail('The :attribute cannot point to internal hosts.');

            return;
        }

        // Block private and reserved IP ranges
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            if (! filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                Log::warning('GitHub URL validation failed - private/reserved IP', [
                    'url' => $value,
                    'host' => $host,
                    'ip' => request()->ip(),
                    'user_id' => auth()->id(),
                ]);
                $fail('The :attribute cannot point to private or reserved IP addresses.');

                return;
            }
        }

        // Block cloud metadata endpoints (common SSRF targets)
        $metadataHosts = ['169.254.169.254', 'metadata.google.internal'];
        if (in_array($host, $metadataHosts)) {
            Log::warning('GitHub URL validation failed - cloud metadata endpoint', [
                'url' => $value,
                'host' => $host,
                'ip' => request()->ip(),
                'user_id' => auth()->id(),
            ]);
            $fail('The :attribute cannot point to cloud metadata endpoints.');

            return;
        }

        // Must not contain userinfo (user:pass@host)
        if (! empty($parsed['user']) || ! empty($parsed['pass'])) {
            $fail('The :attribute must not contain user credentials.');

            return;
        }

        // Must not contain query parameters or fragments
        if (! empty($parsed['query']) || ! empty($parsed['fragment'])) {
            $fail('The :attribute must not contain query parameters or fragments.');

            return;
        }
    }
}
