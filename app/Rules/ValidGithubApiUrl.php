<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Facades\Log;

class ValidGithubApiUrl implements ValidationRule
{
    /**
     * Run the validation rule.
     *
     * Validates that the URL is a safe GitHub API URL, preventing SSRF attacks
     * by blocking internal networks, private IPs, and cloud metadata endpoints.
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

        // Must be HTTPS
        if (! str_starts_with($value, 'https://')) {
            $fail('The :attribute must use HTTPS.');

            return;
        }

        // Must be a valid URL
        if (! filter_var($value, FILTER_VALIDATE_URL)) {
            $fail('The :attribute is not a valid URL.');

            return;
        }

        $parsed = parse_url($value);
        $host = strtolower($parsed['host'] ?? '');

        if (empty($host)) {
            $fail('The :attribute must contain a valid hostname.');

            return;
        }

        // Block localhost and internal hostnames
        $internalHosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
        if (in_array($host, $internalHosts) || str_ends_with($host, '.local') || str_ends_with($host, '.internal')) {
            Log::warning('GitHub API URL validation failed - internal host', [
                'url' => $value,
                'host' => $host,
                'ip' => request()->ip(),
                'user_id' => auth()->id(),
            ]);
            $fail('The :attribute cannot point to internal hosts.');

            return;
        }

        // Block IP addresses (GitHub API always uses hostnames)
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            Log::warning('GitHub API URL validation failed - IP address used', [
                'url' => $value,
                'host' => $host,
                'ip' => request()->ip(),
                'user_id' => auth()->id(),
            ]);
            $fail('The :attribute must use a hostname, not an IP address.');

            return;
        }

        // Resolve hostname and check for private/reserved IP ranges
        $resolvedIps = gethostbynamel($host);
        if ($resolvedIps !== false) {
            foreach ($resolvedIps as $ip) {
                if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    Log::warning('GitHub API URL validation failed - resolves to private/reserved IP', [
                        'url' => $value,
                        'host' => $host,
                        'resolved_ip' => $ip,
                        'ip' => request()->ip(),
                        'user_id' => auth()->id(),
                    ]);
                    $fail('The :attribute resolves to a private or reserved IP address.');

                    return;
                }
            }
        }

        // Block URLs with userinfo (user:pass@host)
        if (! empty($parsed['user']) || ! empty($parsed['pass'])) {
            $fail('The :attribute cannot contain credentials.');

            return;
        }

        // Block URLs with fragments
        if (! empty($parsed['fragment'])) {
            $fail('The :attribute should not contain URL fragments.');

            return;
        }
    }
}
