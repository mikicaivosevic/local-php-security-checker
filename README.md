Online PHP Security Checker
==========================

The Online PHP Security Checker is a tool that checks if your PHP
application depends on PHP packages with known security vulnerabilities. It
uses the [Security Advisories Database][1] behind the scenes.

Forked from [fabpot/local-php-security-checker][2]


Usage

```
curl --data "@/Users/user/Projects/project/composer.lock" http://php-security.abstract.rs/api/v1/check
```

[1]: https://github.com/FriendsOfPHP/security-advisories
[2]: https://github.com/fabpot/local-php-security-checker
