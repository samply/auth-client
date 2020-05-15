# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.0] - 2020-05-14
### Changed
- check id_token_signing_alg_values_supported in addition to request_object_signing_alg_values_supported
  to determine whether or not to use token introspection
- updated auth.dto dependency

## [3.1.2] - 2020-05-08
### Changed
- updated auth.dto dependency

## [3.1.1] - 2020-04-28
### Added
- static method to read OAuth Server config
### Changed
- check supported signing algorithms to determine whether to use token introspection endpoint

## [3.1.0] - 2020-04-27
### Changed
- set auth header for token introspection calls instead of registering a client request filter

## [3.0.0] - 2020-04-24
### Added
- use token introspection endpoint from keycloak to verify tokens
### Changed
- apply google java code style
- updated samply dependencies
- updated parent.pom
### Removed
- internal validation from keycloak tokens

## [2.0.1] - 2019-01-10
### Added
- catch exceptions when trying to get an access token

## [2.0.0] - 2019-01-10
### Added
- added keycloak support
### Changed
- updated samply.auth.dto version

## [1.3.1] - 2016-09-02
### Changed
- updated `Auth.DTO` dependency

## [1.3.0] - 2016-09-02
### Changed
- updated documentation
- updated `Auth.DTO` dependency

## [1.2.0] - 2015-12-21
### Changed
- updated to the latest JOSE JWT library

## [1.1.0] - 2015-11-06
### Added
- maven site documentation
### Changed
- renamed some fields in the UserDTO object
