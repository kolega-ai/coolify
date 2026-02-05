<?php

use App\Rules\ValidGithubApiUrl;
use Illuminate\Support\Facades\Validator;
use Tests\TestCase;

uses(TestCase::class);

it('accepts valid GitHub API URLs', function () {
    $rule = new ValidGithubApiUrl;

    $validUrls = [
        'https://api.github.com',
        'https://api.github.com/',
        'https://github.enterprise.com/api/v3',
        'https://git.example.com/api/v3',
        'https://github.mycompany.com',
    ];

    foreach ($validUrls as $url) {
        $validator = Validator::make(['api_url' => $url], ['api_url' => $rule]);
        expect($validator->passes())->toBeTrue("Failed for URL: {$url}");
    }
});

it('rejects HTTP URLs', function () {
    $rule = new ValidGithubApiUrl;

    $invalidUrls = [
        'http://api.github.com',
        'http://github.enterprise.com/api/v3',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['api_url' => $url], ['api_url' => $rule]);
        expect($validator->fails())->toBeTrue("HTTP URL should be rejected: {$url}");
        expect($validator->errors()->first('api_url'))->toContain('HTTPS');
    }
});

it('rejects non-HTTP protocols', function () {
    $rule = new ValidGithubApiUrl;

    $invalidUrls = [
        'ftp://api.github.com',
        'file:///etc/passwd',
        'gopher://internal-host',
        'dict://internal-host:11111',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['api_url' => $url], ['api_url' => $rule]);
        expect($validator->fails())->toBeTrue("Non-HTTP protocol should be rejected: {$url}");
    }
});

it('rejects localhost and internal hostnames', function () {
    $rule = new ValidGithubApiUrl;

    $invalidUrls = [
        'https://localhost/api/v3',
        'https://127.0.0.1/api/v3',
        'https://0.0.0.0/api/v3',
        'https://example.local/api/v3',
        'https://service.internal/api/v3',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['api_url' => $url], ['api_url' => $rule]);
        expect($validator->fails())->toBeTrue("Internal host should be rejected: {$url}");
    }
});

it('rejects IP addresses', function () {
    $rule = new ValidGithubApiUrl;

    $invalidUrls = [
        'https://192.168.1.1/api/v3',
        'https://10.0.0.1/api/v3',
        'https://172.16.0.1/api/v3',
        'https://169.254.169.254/latest/meta-data/',
        'https://8.8.8.8/api/v3',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['api_url' => $url], ['api_url' => $rule]);
        expect($validator->fails())->toBeTrue("IP address should be rejected: {$url}");
        expect($validator->errors()->first('api_url'))->toContain('hostname');
    }
});

it('rejects URLs with credentials', function () {
    $rule = new ValidGithubApiUrl;

    $invalidUrls = [
        'https://user:pass@github.enterprise.com/api/v3',
        'https://admin@github.enterprise.com/api/v3',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['api_url' => $url], ['api_url' => $rule]);
        expect($validator->fails())->toBeTrue("URL with credentials should be rejected: {$url}");
        expect($validator->errors()->first('api_url'))->toContain('credentials');
    }
});

it('rejects URLs with fragments', function () {
    $rule = new ValidGithubApiUrl;

    $validator = Validator::make(
        ['api_url' => 'https://api.github.com#fragment'],
        ['api_url' => new ValidGithubApiUrl]
    );
    expect($validator->fails())->toBeTrue('URL with fragment should be rejected');
    expect($validator->errors()->first('api_url'))->toContain('fragments');
});

it('accepts empty values', function () {
    $rule = new ValidGithubApiUrl;

    $validator = Validator::make(['api_url' => ''], ['api_url' => $rule]);
    expect($validator->passes())->toBeTrue('Empty URL should be accepted');

    $validator = Validator::make(['api_url' => null], ['api_url' => $rule]);
    expect($validator->passes())->toBeTrue('Null URL should be accepted');
});

it('rejects cloud metadata endpoints', function () {
    $rule = new ValidGithubApiUrl;

    $invalidUrls = [
        'https://169.254.169.254/latest/meta-data/',
        'https://169.254.169.254/',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['api_url' => $url], ['api_url' => $rule]);
        expect($validator->fails())->toBeTrue("Cloud metadata endpoint should be rejected: {$url}");
    }
});

it('rejects invalid URL formats', function () {
    $rule = new ValidGithubApiUrl;

    $invalidUrls = [
        'not-a-url',
        'https://',
        'just-text',
    ];

    foreach ($invalidUrls as $url) {
        $validator = Validator::make(['api_url' => $url], ['api_url' => $rule]);
        expect($validator->fails())->toBeTrue("Invalid URL format should be rejected: {$url}");
    }
});
