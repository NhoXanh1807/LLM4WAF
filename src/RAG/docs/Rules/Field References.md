---
title: Fields reference · Cloudflare Ruleset Engine docs
chatbotDeprioritize: false
source_url:
  html: https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/
  md: https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/index.md
---

Categories

[cf.api\_gateway.auth\_id\_present](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.api_gateway.auth_id_present/)

[Indicates whether the request contained an API session authentication token, as defined by API Shield's saved session identifiers.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.api_gateway.auth_id_present/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.api_gateway.auth_id_present/)

[cf.api\_gateway.fallthrough\_detected](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.api_gateway.fallthrough_detected/)

[Indicates whether the request matched a saved endpoint in Endpoint Management.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.api_gateway.fallthrough_detected/)

[cf.api\_gateway.request\_violates\_schema](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.api_gateway.request_violates_schema/)

[Indicates whether the request violated the schema assigned to the respective saved endpoint.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.api_gateway.request_violates_schema/)

[cf.bot\_management.corporate\_proxy](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.corporate_proxy/)

[Indicates whether the incoming request comes from an identified Enterprise-only cloud-based corporate proxy or secure web gateway.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.corporate_proxy/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.corporate_proxy/)

[cf.bot\_management.detection\_ids](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.detection_ids/)

[List of IDs that correlate to the Bot Management heuristic detections made on a request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.detection_ids/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.detection_ids/)

[cf.bot\_management.ja3\_hash](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.ja3_hash/)

[Provides an SSL/TLS fingerprint to help you identify potential bot requests.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.ja3_hash/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.ja3_hash/)

[cf.bot\_management.ja4](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.ja4/)

[Provides an SSL/TLS fingerprint to help you identify potential bot requests.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.ja4/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.ja4/)

[cf.bot\_management.js\_detection.passed](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.js_detection.passed/)

[Indicates whether the visitor has previously passed a JS Detection.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.js_detection.passed/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.js_detection.passed/)

[cf.bot\_management.score](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.score/)

[Represents the likelihood that a request originates from a bot using a score from 1–99.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.score/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.score/)

[cf.bot\_management.static\_resource](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.static_resource/)

[Indicates whether static resources should be included when you create a rule using `cf.bot_management.score`.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.static_resource/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.static_resource/)

[cf.bot\_management.verified\_bot](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.verified_bot/)

[Indicates whether the request originated from a known good bot or crawler.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.verified_bot/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.verified_bot/)

[cf.client.bot](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.client.bot/)

[Indicates whether the request originated from a known good bot or crawler.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.client.bot/)

[cf.edge.client\_tcp](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.edge.client_tcp/)

[Indicates if the request was made over TCP.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.edge.client_tcp/)

[cf.edge.server\_ip](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.edge.server_ip/)

[Represents the global network's IP address to which the HTTP request has resolved.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.edge.server_ip/)

[cf.edge.server\_port](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.edge.server_port/)

[Represents the port number at which the Cloudflare global network received the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.edge.server_port/)

[cf.hostname.metadata](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.hostname.metadata/)

[Returns the string representation of the per-hostname custom metadata JSON object set by SSL for SaaS customers.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.hostname.metadata/)

[cf.llm.prompt.detected](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.detected/)

[Indicates whether Cloudflare detected an LLM prompt in the incoming request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.detected/)

[* Enterprise](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.detected/)

[cf.llm.prompt.injection\_score](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.injection_score/)

[A score from 1–99 that represents the likelihood that the LLM prompt in the request is trying to perform a prompt injection attack.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.injection_score/)

[* Enterprise](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.injection_score/)

[cf.llm.prompt.pii\_categories](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.pii_categories/)

[Array of string values with the personally identifiable information (PII) categories found in the LLM prompt included in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.pii_categories/)

[* Enterprise](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.pii_categories/)

[cf.llm.prompt.pii\_detected](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.pii_detected/)

[Indicates whether any personally identifiable information (PII) has been detected in the LLM prompt included in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.pii_detected/)

[* Enterprise](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.pii_detected/)

[cf.llm.prompt.unsafe\_topic\_categories](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.unsafe_topic_categories/)

[Array of string values with the type of unsafe topics detected in the LLM prompt.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.unsafe_topic_categories/)

[* Enterprise](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.unsafe_topic_categories/)

[cf.llm.prompt.unsafe\_topic\_detected](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.unsafe_topic_detected/)

[Indicates whether the incoming request includes any unsafe topic category in the LLM prompt.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.unsafe_topic_detected/)

[* Enterprise](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.llm.prompt.unsafe_topic_detected/)

[cf.random\_seed](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.random_seed/)

[Returns per-request random bytes that you can use in the `uuidv4()` function.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.random_seed/)

[cf.ray\_id](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.ray_id/)

[The Ray ID of the current request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.ray_id/)

[cf.response.1xxx\_code](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.response.1xxx_code/)

[Contains the specific code for 1XXX Cloudflare errors.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.response.1xxx_code/)

[cf.response.error\_type](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.response.error_type/)

[A string with the type of error in the response being returned.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.response.error_type/)

[cf.threat\_score](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.threat_score/)

[Represents a Cloudflare threat score.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.threat_score/)

[cf.timings.client\_tcp\_rtt\_msec](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.timings.client_tcp_rtt_msec/)

[The smoothed TCP round-trip time (RTT) from client to Cloudflare in milliseconds.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.timings.client_tcp_rtt_msec/)

[cf.timings.edge\_msec](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.timings.edge_msec/)

[The time spent processing a request within the Cloudflare global network in milliseconds.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.timings.edge_msec/)

[cf.timings.origin\_ttfb\_msec](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.timings.origin_ttfb_msec/)

[The round-trip time (RTT) between the Cloudflare global network and the origin server in milliseconds.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.timings.origin_ttfb_msec/)

[cf.tls\_cipher](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_cipher/)

[The cipher for the connection to Cloudflare.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_cipher/)

[cf.tls\_ciphers\_sha1](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_ciphers_sha1/)

[The SHA-1 fingerprint of the client TLS cipher list in received order, encoded in Base64 using big-endian format.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_ciphers_sha1/)

[cf.tls\_client\_auth.cert\_fingerprint\_sha1](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_fingerprint_sha1/)

[The SHA-1 fingerprint of the certificate in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_fingerprint_sha1/)

[cf.tls\_client\_auth.cert\_fingerprint\_sha256](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_fingerprint_sha256/)

[The SHA-256 fingerprint of the certificate in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_fingerprint_sha256/)

[cf.tls\_client\_auth.cert\_issuer\_dn](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_issuer_dn/)

[The Distinguished Name (DN) of the Certificate Authority (CA) that issued the certificate included in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_issuer_dn/)

[cf.tls\_client\_auth.cert\_issuer\_dn\_legacy](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_issuer_dn_legacy/)

[The Distinguished Name (DN) of the Certificate Authority (CA) that issued the certificate in the request in a legacy format.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_issuer_dn_legacy/)

[cf.tls\_client\_auth.cert\_issuer\_dn\_rfc2253](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_issuer_dn_rfc2253/)

[The Distinguished Name (DN) of the Certificate Authority (CA) that issued the certificate in the request in RFC 2253 format.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_issuer_dn_rfc2253/)

[cf.tls\_client\_auth.cert\_issuer\_serial](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_issuer_serial/)

[Serial number of the direct issuer of the certificate in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_issuer_serial/)

[cf.tls\_client\_auth.cert\_issuer\_ski](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_issuer_ski/)

[The Subject Key Identifier (SKI) of the direct issuer of the certificate in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_issuer_ski/)

[cf.tls\_client\_auth.cert\_not\_after](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_not_after/)

[The certificate in the request is not valid after this date.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_not_after/)

[cf.tls\_client\_auth.cert\_not\_before](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_not_before/)

[The certificate in the request is not valid before this date.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_not_before/)

[cf.tls\_client\_auth.cert\_presented](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_presented/)

[Returns `true` when a request presents a certificate (valid or not).](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_presented/)

[cf.tls\_client\_auth.cert\_revoked](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_revoked/)

[Indicates whether the request presented a valid but revoked client certificate.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_revoked/)

[cf.tls\_client\_auth.cert\_serial](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_serial/)

[Serial number of the certificate in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_serial/)

[cf.tls\_client\_auth.cert\_ski](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_ski/)

[The Subject Key Identifier (SKI) of the certificate in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_ski/)

[cf.tls\_client\_auth.cert\_subject\_dn](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_subject_dn/)

[The Distinguished Name (DN) of the owner (or requester) of the certificate included in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_subject_dn/)

[cf.tls\_client\_auth.cert\_subject\_dn\_legacy](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_subject_dn_legacy/)

[The Distinguished Name (DN) of the owner (or requester) of the certificate in the request in a legacy format.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_subject_dn_legacy/)

[cf.tls\_client\_auth.cert\_subject\_dn\_rfc2253](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_subject_dn_rfc2253/)

[The Distinguished Name (DN) of the owner (or requester) of the certificate in the request in RFC 2253 format.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_subject_dn_rfc2253/)

[cf.tls\_client\_auth.cert\_verified](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_verified/)

[Returns `true` when a request presents a valid client certificate.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_verified/)

[cf.tls\_client\_extensions\_sha1](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_extensions_sha1/)

[The SHA-1 fingerprint of TLS client extensions, encoded in Base64 using big-endian format.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_extensions_sha1/)

[cf.tls\_client\_extensions\_sha1\_le](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_extensions_sha1_le/)

[The SHA-1 fingerprint of TLS client extensions, encoded in Base64 using little-endian format.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_extensions_sha1_le/)

[cf.tls\_client\_hello\_length](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_hello_length/)

[The length of the client hello message sent in a TLS handshake.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_hello_length/)

[cf.tls\_client\_random](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_random/)

[The value of the 32-byte random value provided by the client in a TLS handshake, encoded in Base64.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_random/)

[cf.tls\_version](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_version/)

[The TLS version of the connection to Cloudflare.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_version/)

[cf.verified\_bot\_category](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.verified_bot_category/)

[Provides the type and purpose of a verified bot.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.verified_bot_category/)

[cf.waf.auth\_detected](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.auth_detected/)

[Indicates whether the Cloudflare WAF detected authentication credentials in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.auth_detected/)

[* Enterprise](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.auth_detected/)

[cf.waf.content\_scan.has\_failed](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.has_failed/)

[Indicates whether the file scanner was unable to scan any of the content objects detected in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.has_failed/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.has_failed/)

[cf.waf.content\_scan.has\_malicious\_obj](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.has_malicious_obj/)

[Indicates whether the request contains at least one malicious content object.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.has_malicious_obj/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.has_malicious_obj/)

[cf.waf.content\_scan.has\_obj](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.has_obj/)

[Indicates whether the request contains at least one content object.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.has_obj/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.has_obj/)

[cf.waf.content\_scan.num\_malicious\_obj](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.num_malicious_obj/)

[The number of malicious content objects detected in the request (zero or greater).](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.num_malicious_obj/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.num_malicious_obj/)

[cf.waf.content\_scan.num\_obj](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.num_obj/)

[The number of content objects detected in the request (zero or greater).](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.num_obj/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.num_obj/)

[cf.waf.content\_scan.obj\_results](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.obj_results/)

[An array of scan results in the order the content objects were detected in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.obj_results/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.obj_results/)

[cf.waf.content\_scan.obj\_sizes](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.obj_sizes/)

[An array of file sizes in bytes, in the order the content objects were detected in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.obj_sizes/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.obj_sizes/)

[cf.waf.content\_scan.obj\_types](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.obj_types/)

[An array of file types in the order the content objects were detected in the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.obj_types/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.content_scan.obj_types/)

[cf.waf.credential\_check.password\_leaked](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.credential_check.password_leaked/)

[Indicates whether the password detected in the request was previously leaked.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.credential_check.password_leaked/)

[cf.waf.credential\_check.username\_and\_password\_leaked](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.credential_check.username_and_password_leaked/)

[Indicates whether the auth credentials detected in the request (username-password pair) were previously leaked.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.credential_check.username_and_password_leaked/)

[* Pro or above](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.credential_check.username_and_password_leaked/)

[cf.waf.credential\_check.username\_leaked](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.credential_check.username_leaked/)

[Indicates whether the username detected in the request was previously leaked.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.credential_check.username_leaked/)

[* Enterprise](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.credential_check.username_leaked/)

[cf.waf.credential\_check.username\_password\_similar](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.credential_check.username_password_similar/)

[Indicates whether a similar version of the username and password credentials detected in the request were previously leaked.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.credential_check.username_password_similar/)

[* Enterprise](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.credential_check.username_password_similar/)

[cf.waf.score](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score/)

[A global score from 1–99 that combines the score of each WAF attack vector into a single score.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score/)

[* Enterprise](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score/)

[cf.waf.score.class](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score.class/)

[The attack score class of the current request, based on the WAF attack score.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score.class/)

[* Business or above](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score.class/)

[cf.waf.score.rce](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score.rce/)

[An attack score from 1–99 classifying the command injection or Remote Code Execution (RCE) attack vector.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score.rce/)

[* Enterprise](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score.rce/)

[cf.waf.score.sqli](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score.sqli/)

[An attack score from 1–99 classifying the SQL injection (SQLi) attack vector.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score.sqli/)

[* Enterprise](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score.sqli/)

[cf.waf.score.xss](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score.xss/)

[An attack score from 1–99 classifying the cross-site scripting (XSS) attack vector.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score.xss/)

[* Enterprise](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score.xss/)

[cf.worker.upstream\_zone](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.worker.upstream_zone/)

[Identifies whether a request comes from a worker or not.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.worker.upstream_zone/)

[http.cookie](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.cookie/)

[The entire cookie as a string.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.cookie/)

[http.host](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.host/)

[The hostname used in the full request URI.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.host/)

[http.referer](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.referer/)

[The HTTP `Referer` request header, which contains the address of the web page that linked to the currently requested page.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.referer/)

[http.request.accepted\_languages](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.accepted_languages/)

[List of language tags provided in the `Accept-Language` HTTP request header.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.accepted_languages/)

[http.request.body.form](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.form/)

[The HTTP request body of a form represented as a Map (or associative array).](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.form/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.form/)

[http.request.body.form.names](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.form.names/)

[The names of the form fields in an HTTP request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.form.names/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.form.names/)

[http.request.body.form.values](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.form.values/)

[The values of the form fields in an HTTP request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.form.values/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.form.values/)

[http.request.body.mime](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.mime/)

[The MIME type of the request detected from the request body.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.mime/)

[http.request.body.multipart](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart/)

[A Map (or associative array) representation of multipart names to multipart values in the request body.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart/)

[http.request.body.multipart.content\_dispositions](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.content_dispositions/)

[List of `Content-Disposition` headers for each part in the multipart body.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.content_dispositions/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.content_dispositions/)

[http.request.body.multipart.content\_transfer\_encodings](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.content_transfer_encodings/)

[List of `Content-Transfer-Encoding` headers for each part in the multipart body.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.content_transfer_encodings/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.content_transfer_encodings/)

[http.request.body.multipart.content\_types](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.content_types/)

[List of `Content-Type` headers for each part in the multipart body.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.content_types/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.content_types/)

[http.request.body.multipart.filenames](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.filenames/)

[List of filenames for each part in the multipart body.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.filenames/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.filenames/)

[http.request.body.multipart.names](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.names/)

[List of multipart names for every part in the multipart body.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.names/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.names/)

[http.request.body.multipart.values](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.values/)

[List of multipart values for every part in the multipart body.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.values/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.values/)

[http.request.body.raw](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.raw/)

[The unaltered HTTP request body.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.raw/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.raw/)

[http.request.body.size](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.size/)

[The total size of the HTTP request body (in bytes).](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.size/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.size/)

[http.request.body.truncated](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.truncated/)

[Indicates whether the HTTP request body is truncated.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.truncated/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.truncated/)

[http.request.cookies](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.cookies/)

[The `Cookie` HTTP header associated with a request represented as a Map (associative array).](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.cookies/)

[* Pro or above](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.cookies/)

[http.request.full\_uri](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.full_uri/)

[The full URI as received by the web server.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.full_uri/)

[http.request.headers](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.headers/)

[The HTTP request headers represented as a Map (or associative array).](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.headers/)

[http.request.headers.names](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.headers.names/)

[The names of the headers in the HTTP request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.headers.names/)

[http.request.headers.truncated](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.headers.truncated/)

[Indicates whether the HTTP request contains too many headers.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.headers.truncated/)

[http.request.headers.values](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.headers.values/)

[The values of the headers in the HTTP request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.headers.values/)

[http.request.jwt.claims.aud](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.aud/)

[The `aud` (audience) claim identifies the recipients that the JSON Web Token (JWT) is intended for.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.aud/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.aud/)

[http.request.jwt.claims.aud.names](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.aud.names/)

[The `aud` (audience) claim identifies the recipients that the JSON Web Token (JWT) is intended for.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.aud.names/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.aud.names/)

[http.request.jwt.claims.aud.values](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.aud.values/)

[The `aud` (audience) claim identifies the recipients that the JSON Web Token (JWT) is intended for.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.aud.values/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.aud.values/)

[http.request.jwt.claims.iat.sec](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iat.sec/)

[The `iat` (issued at) claim identifies the time (number of seconds) at which the JWT was issued.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iat.sec/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iat.sec/)

[http.request.jwt.claims.iat.sec.names](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iat.sec.names/)

[The `iat` (issued at) claim identifies the time (number of seconds) at which the JWT was issued.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iat.sec.names/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iat.sec.names/)

[http.request.jwt.claims.iat.sec.values](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iat.sec.values/)

[The `iat` (issued at) claim identifies the time (number of seconds) at which the JWT was issued.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iat.sec.values/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iat.sec.values/)

[http.request.jwt.claims.iss](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iss/)

[The `iss` (issuer) claim identifies the principal that issued the JWT.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iss/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iss/)

[http.request.jwt.claims.iss.names](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iss.names/)

[The `iss` (issuer) claim identifies the principal that issued the JWT.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iss.names/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iss.names/)

[http.request.jwt.claims.iss.values](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iss.values/)

[The `iss` (issuer) claim identifies the principal that issued the JWT.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iss.values/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.iss.values/)

[http.request.jwt.claims.jti](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.jti/)

[The `jti` (JWT ID) claim provides a unique identifier for the JWT.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.jti/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.jti/)

[http.request.jwt.claims.jti.names](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.jti.names/)

[The `jti` (JWT ID) claim provides a unique identifier for the JWT.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.jti.names/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.jti.names/)

[http.request.jwt.claims.jti.values](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.jti.values/)

[The `jti` (JWT ID) claim provides a unique identifier for the JWT.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.jti.values/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.jti.values/)

[http.request.jwt.claims.nbf.sec](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.nbf.sec/)

[The `nbf` (not before) claim identifies the time (number of seconds) before which the JWT must not be accepted for processing.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.nbf.sec/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.nbf.sec/)

[http.request.jwt.claims.nbf.sec.names](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.nbf.sec.names/)

[The `nbf` (not before) claim identifies the time (number of seconds) before which the JWT must not be accepted for processing.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.nbf.sec.names/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.nbf.sec.names/)

[http.request.jwt.claims.nbf.sec.values](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.nbf.sec.values/)

[The `nbf` (not before) claim identifies the time (number of seconds) before which the JWT must not be accepted for processing.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.nbf.sec.values/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.nbf.sec.values/)

[http.request.jwt.claims.sub](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.sub/)

[The `sub` (subject) claim identifies the principal that is the subject of the JWT.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.sub/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.sub/)

[http.request.jwt.claims.sub.names](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.sub.names/)

[The `sub` (subject) claim identifies the principal that is the subject of the JWT.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.sub.names/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.sub.names/)

[http.request.jwt.claims.sub.values](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.sub.values/)

[The `sub` (subject) claim identifies the principal that is the subject of the JWT.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.sub.values/)

[* Enterprise add-on](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.jwt.claims.sub.values/)

[http.request.method](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.method/)

[The HTTP method, returned as a string of uppercase characters.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.method/)

[http.request.timestamp.msec](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.timestamp.msec/)

[The millisecond when Cloudflare received the request, between 0–999.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.timestamp.msec/)

[http.request.timestamp.sec](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.timestamp.sec/)

[The timestamp when Cloudflare received the request, expressed as UNIX time in seconds.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.timestamp.sec/)

[http.request.uri](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri/)

[The URI path and query string of the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri/)

[http.request.uri.args](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri.args/)

[The HTTP URI arguments associated with a request represented as a Map (associative array).](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri.args/)

[http.request.uri.args.names](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri.args.names/)

[The names of the arguments in the HTTP URI query string.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri.args.names/)

[http.request.uri.args.values](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri.args.values/)

[The values of arguments in the HTTP URI query string.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri.args.values/)

[http.request.uri.path](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri.path/)

[The URI path of the request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri.path/)

[http.request.uri.path.extension](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri.path.extension/)

[The lowercased file extension in the URI path without the dot (`.`) character.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri.path.extension/)

[http.request.uri.query](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri.query/)

[The entire query string, without the `?` delimiter.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri.query/)

[http.request.version](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.version/)

[The version of the HTTP protocol used. Use this field when different checks are needed for different versions.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.version/)

[http.response.code](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.response.code/)

[The HTTP status code returned to the client, either set by a Cloudflare product or returned by the origin server.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.response.code/)

[http.response.content\_type.media\_type](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.response.content_type.media_type/)

[The lowercased content type (including subtype and suffix) without any extra parameters, based on the response's `Content-Type` header.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.response.content_type.media_type/)

[http.response.headers](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.response.headers/)

[The HTTP response headers represented as a Map (or associative array).](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.response.headers/)

[http.response.headers.names](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.response.headers.names/)

[The names of the headers in the HTTP response.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.response.headers.names/)

[http.response.headers.values](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.response.headers.values/)

[The values of the headers in the HTTP response.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.response.headers.values/)

[http.user\_agent](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.user_agent/)

[The HTTP `User-Agent` request header, which contains a characteristic string to identify the client operating system and web browser.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.user_agent/)

[http.x\_forwarded\_for](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.x_forwarded_for/)

[The full value of the `X-Forwarded-For` HTTP header.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.x_forwarded_for/)

[ip.src](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src/)

[The client TCP IP address, which may be adjusted to reflect the actual address of the client using HTTP headers such as `X-Forwarded-For` or `X-Real-IP`.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src/)

[ip.src.asnum](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.asnum/)

[The 16-bit or 32-bit integer representing the Autonomous System (AS) number associated with the client IP address.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.asnum/)

[ip.src.city](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.city/)

[The city associated with the client IP address.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.city/)

[ip.src.continent](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.continent/)

[The continent code associated with the client IP address.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.continent/)

[ip.src.country](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.country/)

[The 2-letter country code in ISO 3166-1 Alpha 2 format.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.country/)

[ip.src.is\_in\_european\_union](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.is_in_european_union/)

[Whether the request originates from a country in the European Union (EU).](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.is_in_european_union/)

[* Business or above](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.is_in_european_union/)

[ip.src.lat](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.lat/)

[The latitude associated with the client IP address.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.lat/)

[ip.src.lon](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.lon/)

[The longitude associated with the client IP address.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.lon/)

[ip.src.metro\_code](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.metro_code/)

[The metro code or Designated Market Area (DMA) code associated with the incoming request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.metro_code/)

[ip.src.postal\_code](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.postal_code/)

[The postal code associated with the incoming request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.postal_code/)

[ip.src.region](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.region/)

[The region name associated with the incoming request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.region/)

[ip.src.region\_code](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.region_code/)

[The region code associated with the incoming request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.region_code/)

[ip.src.subdivision\_1\_iso\_code](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.subdivision_1_iso_code/)

[The ISO 3166-2 code for the first-level region associated with the IP address.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.subdivision_1_iso_code/)

[* Business or above](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.subdivision_1_iso_code/)

[ip.src.subdivision\_2\_iso\_code](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.subdivision_2_iso_code/)

[The ISO 3166-2 code for the second-level region associated with the IP address.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.subdivision_2_iso_code/)

[* Business or above](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.subdivision_2_iso_code/)

[ip.src.timezone.name](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.timezone.name/)

[The name of the timezone associated with the incoming request.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.timezone.name/)

[raw.http.request.full\_uri](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.full_uri/)

[The raw full URI as received by the web server without any transformation.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.full_uri/)

[raw.http.request.uri](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri/)

[The URI path and query string of the request without any transformation.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri/)

[raw.http.request.uri.args](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri.args/)

[The raw HTTP URI arguments associated with a request represented as a Map (associative array).](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri.args/)

[raw.http.request.uri.args.names](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri.args.names/)

[The raw names of the arguments in the HTTP URI query string.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri.args.names/)

[raw.http.request.uri.args.values](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri.args.values/)

[The raw values of arguments in the HTTP URI query string.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri.args.values/)

[raw.http.request.uri.path](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri.path/)

[The raw URI path of the request without any transformation.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri.path/)

[raw.http.request.uri.path.extension](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri.path.extension/)

[The raw file extension in the request URI path without any transformation.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri.path.extension/)

[raw.http.request.uri.query](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri.query/)

[The entire query string without the `?` delimiter and without any transformation.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.request.uri.query/)

[raw.http.response.headers](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.response.headers/)

[The HTTP response headers without any transformation represented as a Map (or associative array).](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.response.headers/)

[raw.http.response.headers.names](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.response.headers.names/)

[The names of the headers in the HTTP response without any transformation.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.response.headers.names/)

[raw.http.response.headers.values](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.response.headers.values/)

[The values of the headers in the HTTP response without any transformation.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/raw.http.response.headers.values/)

[ssl](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ssl/)

[Returns `true` when the HTTP connection to the client is encrypted.](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ssl/)
