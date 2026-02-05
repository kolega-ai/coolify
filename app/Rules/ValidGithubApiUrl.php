<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Facades\Log;

class ValidGithubApiUrl implements ValidationRule
{
    /**
     * Run the validation rule.
     */
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (empty($value)) {
            return;
        }

        // Must be a valid URL
        if (! filter_var($value, FILTER_VALIDATE_URL)) {
            $fail('The :attribute is not a valid URL.');

            return;
        }

        $parsed = parse_url($value);

        // Must use HTTPS protocol
        if (($parsed['scheme'] ?? '') !== 'https') {
            Log::warning('GitHub API URL validation failed - not HTTPS', [
                'url' => $value,
                'ip' => request()?->ip(),
                'user_id' => auth()?->id(),
            ]);
            $fail('The :attribute must use HTTPS protocol.');

            return;
        }

        $host = strtolower($parsed['host'] ?? '');

        // Check for IP addresses - reject all IP addresses
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            Log::warning('GitHub API URL validation failed - IP address not allowed', [
                'url' => $value,
                'host' => $host,
                'ip' => request()?->ip(),
                'user_id' => auth()?->id(),
            ]);
            $fail('The :attribute cannot use IP addresses.');

            return;
        }

        // Check for localhost/internal hosts
        $internalHosts = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '::1',
            '[::1]',
        ];

        if (in_array($host, $internalHosts) || str_ends_with($host, '.local')) {
            Log::warning('GitHub API URL validation failed - internal host', [
                'url' => $value,
                'host' => $host,
                'ip' => request()?->ip(),
                'user_id' => auth()?->id(),
            ]);
            $fail('The :attribute cannot point to internal hosts.');

            return;
        }

        // Check for private/internal IP ranges via DNS resolution
        // This prevents SSRF attacks where an attacker uses a domain that resolves to internal IPs
        if ($this->resolvesToPrivateIp($host)) {
            Log::warning('GitHub API URL validation failed - resolves to private IP', [
                'url' => $value,
                'host' => $host,
                'ip' => request()?->ip(),
                'user_id' => auth()?->id(),
            ]);
            $fail('The :attribute cannot resolve to private IP addresses.');

            return;
        }
    }

    /**
     * Check if a hostname resolves to a private IP address.
     */
    private function resolvesToPrivateIp(string $host): bool
    {
        // Get all IP addresses for the host
        $ipAddresses = $this->getIpAddresses($host);

        foreach ($ipAddresses as $ip) {
            // Check if IP is in private/reserved ranges
            if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get IP addresses for a hostname using DNS resolution.
     *
     * @return array<string>
     */
    private function getIpAddresses(string $host): array
    {
        $ips = [];

        // Try to get IPv4 addresses
        $dnsRecords = dns_get_record($host, DNS_A);
        if ($dnsRecords !== false) {
            foreach ($dnsRecords as $record) {
                if (isset($record['ip'])) {
                    $ips[] = $record['ip'];
                }
            }
        }

        // Try to get IPv6 addresses
        $dnsRecords = dns_get_record($host, DNS_AAAA);
        if ($dnsRecords !== false) {
            foreach ($dnsRecords as $record) {
                if (isset($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }

        // If no DNS records found, try gethostbyname as fallback
        if (empty($ips)) {
            $ip = gethostbyname($host);
            if ($ip !== $host && filter_var($ip, FILTER_VALIDATE_IP)) {
                $ips[] = $ip;
            }
        }

        return $ips;
    }
}
