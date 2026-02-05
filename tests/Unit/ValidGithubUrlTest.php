<?php

use App\Rules\ValidGithubUrl;
use Illuminate\Support\Facades\Validator;
use Tests\TestCase;

uses(TestCase::class);

it('accepts valid GitHub API and HTML URLs', function () {
    $rule = new ValidGithubUrl;

    $validUrls = [
        'https://api.github.com',
        'https://github.com',
        'https://github.example.com',
        'https://api.github.example.com',
        'https://github.enterprise.example.com',
        'https://github.example.com/api/v3',
    ];

    foreach ($validUrls as $url) {
        $validator = Validator::make(['url' => $url], ['url' => $rule]);
        expect($validator->passes())->toBeTrue("Failed for valid URL: {$url}");
    }
});

it('rejects non-HTTPS URLs', function () {
    $rule = new ValidGithubUrl;

    $invalidUrls = [
        'http://api.github.com',
        'http://github.com',
        'ftp://github.com',
        'git://github.com',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['url' => $url], ['url' => $rule]);
        expect($validator->fails())->toBeTrue("Non-HTTPS URL should be rejected: {$url}");
        expect($validator->errors()->first('url'))->toContain('HTTPS');
    }
});

it('rejects localhost and internal hostnames', function () {
    $rule = new ValidGithubUrl;

    $invalidUrls = [
        'https://localhost',
        'https://localhost/api/v3',
        'https://127.0.0.1',
        'https://0.0.0.0',
        'https://example.local',
        'https://myhost.local/api',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['url' => $url], ['url' => $rule]);
        expect($validator->fails())->toBeTrue("Internal host URL should be rejected: {$url}");
    }
});

it('rejects private IP ranges', function () {
    $rule = new ValidGithubUrl;

    $invalidUrls = [
        'https://10.0.0.1',
        'https://10.255.255.255',
        'https://172.16.0.1',
        'https://172.31.255.255',
        'https://192.168.0.1',
        'https://192.168.255.255',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['url' => $url], ['url' => $rule]);
        expect($validator->fails())->toBeTrue("Private IP URL should be rejected: {$url}");
        expect($validator->errors()->first('url'))->toContain('private or reserved IP');
    }
});

it('rejects cloud metadata endpoints', function () {
    $rule = new ValidGithubUrl;

    $invalidUrls = [
        'https://169.254.169.254',
        'https://169.254.169.254/latest/meta-data/',
        'https://metadata.google.internal',
        'https://metadata.google.internal/computeMetadata/v1/',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['url' => $url], ['url' => $rule]);
        expect($validator->fails())->toBeTrue("Cloud metadata URL should be rejected: {$url}");
    }
});

it('rejects URLs with user credentials', function () {
    $rule = new ValidGithubUrl;

    $invalidUrls = [
        'https://user:pass@github.com',
        'https://admin@github.com',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['url' => $url], ['url' => $rule]);
        expect($validator->fails())->toBeTrue("URL with credentials should be rejected: {$url}");
        expect($validator->errors()->first('url'))->toContain('user credentials');
    }
});

it('rejects URLs with query parameters or fragments', function () {
    $rule = new ValidGithubUrl;

    $invalidUrls = [
        'https://api.github.com?redirect=http://evil.com',
        'https://api.github.com#fragment',
        'https://github.com?token=abc123',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['url' => $url], ['url' => $rule]);
        expect($validator->fails())->toBeTrue("URL with query/fragment should be rejected: {$url}");
    }
});

it('rejects invalid URL formats', function () {
    $rule = new ValidGithubUrl;

    $invalidUrls = [
        'not-a-url',
        'just-text',
        '://missing-scheme',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['url' => $url], ['url' => $rule]);
        expect($validator->fails())->toBeTrue("Invalid URL format should be rejected: {$url}");
    }
});

it('accepts empty values', function () {
    $rule = new ValidGithubUrl;

    $validator = Validator::make(['url' => ''], ['url' => $rule]);
    expect($validator->passes())->toBeTrue('Empty URL should be accepted');

    $validator = Validator::make(['url' => null], ['url' => $rule]);
    expect($validator->passes())->toBeTrue('Null URL should be accepted');
});

it('rejects ::1 IPv6 loopback', function () {
    $rule = new ValidGithubUrl;

    $validator = Validator::make(['url' => 'https://[::1]'], ['url' => $rule]);
    expect($validator->fails())->toBeTrue('IPv6 loopback should be rejected');
});
