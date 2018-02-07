[![Build Status](https://travis-ci.org/jban332/kin-auth.svg?branch=master)](https://travis-ci.org/jban332/kin-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/jban332/kin-auth)](https://goreportcard.com/report/github.com/jban332/kin-auth)
[![GoDoc](https://godoc.org/github.com/jban332/kin-auth?status.svg)](https://godoc.org/github.com/jban332/kin-auth)

# Overview
* An authentication package for Go.
* Close integration with [kin-openapi](https://github.com/jban332/kin-openapi), and OpenAPI 3 implementation for Go.

## Drivers
### Web standards
  * `csrf`
    * [Cross-Site Request Forgery](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)) protection
    * By default, uses cookie "XSRF-TOKEN".
    * You define HTTP header name in your OpenAPI schema.
  * `apikey`
    * Checks HTTP header "Authorization".
    * Your define how to check that the token is valid.
  * `oauth2`
    * Built-in configurations for many providers (see below)
    * Your define details in your OpenAPI security scheme. We provide a number of predefined OpenAPI security schemes.
  * `session`
    * Authentication information is stored in a JWT header or cookie.

### Non-standard
  * `gae`
    * Google App Engine authentication

## Predefined OpenAPI security schemes
Package `openapi3auth` defines the following OpenAPI 3 security schemes.

### csrf
  * Cross-Site Request Forgery protection

### gae
  * Google App Engine authentication
  * You must separately import _driver/gae_.
  * Configure with environmental variables:
    * OAUTH2_GAE_ID
	* OAUTH2_GAE_SECRET

### google
  * Google OAuth2 authentication
  * Configure with environmental variables:
    * OAUTH2_GOOGLE_ID
	* OAUTH2_GOOGLE_SECRET

### facebook
  * Facebook OAuth2 authentication
  * Configure with environmental variables:
    * OAUTH2_FACEBOOK_ID
	* OAUTH2_FACEBOOK_SECRET
    * OAUTH2_FACEBOOK_PROOF_SECRET

### linkedin
  * Linkedin OAuth2 authentication
  * Configure with environmental variables:
    * OAUTH2_LINKEDIN_ID
	* OAUTH2_LINKEDIN_SECRET

### twitter
  * Twitter OAuth2 authentication
  * Configure with environmental variables:
    * OAUTH2_TWITTER_ID
	* OAUTH2_TWITTER_SECRET

## Dependencies
  * [kin-openapi](https://github.com/jban332/kin-openapi)
  * [kin-log](https://github.com/jban332/kin-log) (will be removed in future)

# Getting started
See [kin-openapi](https://github.com/jban332/kin-openapi) documentation.
