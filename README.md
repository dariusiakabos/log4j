# Log4J Zero-Day
Compilation of log4j OSINT findings, including Detection, Attack Surface, Mitigation, IoCs.
# I. Overview
## Affected versions:
- Apache Log4j v2.0 -> v2.14.1
- Anyone using Apache Struts framework is likely vulnerable

### Main blog covering this: 
https://www.lunasec.io/docs/blog/log4j-zero-day/
### Collection of information on log4j, including affected products
https://www.techsolvency.com/story-so-far/cve-2021-44228-log4j-log4shell/ - by @TychoTithonus (Royce Williams).

## Attack surface
A compilation of exploit examples.
https://github.com/YfryTchsGD/Log4jAttackSurface

# II. Detection

Resources by Florian Roth (comment section also contains usefull info)
https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b

## Log4Shell Detector V0.5 by Florian Roth
https://github.com/Neo23x0/log4shell-detector

Hashes for vulneraable log4j versions
https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes

Swiss CERT guidelines for detecting and preventing
https://www.govcert.admin.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/

## Testing apps for log4shell vuln
### a) Canarytokens
#### Automatic:
https://twitter.com/ThinkstCanary/status/1469439743905697797
You can use a point & click canarytoken from https://canarytokens.org to help test for the #log4j  / #Log4Shell issue.

1) visit https://canarytokens.org;
2) choose the Log4shell token;
3) enter the email address you wish to be notified at;
4) copy/use the returned string...

#### Manual
1. Generate a DNS token https://canarytokens.org/generate#
2. Wrap that token in 
Prefix: ${jndi:ldap://
Suffix: /a}
3. Use that value in search forms, profile data, settings etc. of your apps
4. Get notified when you triggered a reaction

### b) Huntress Log4Shell Vulnerability Tester
Details on their page
https://log4shell.huntress.com/

## Some semgrep rules for searching Java source code for vulnerable code paths.
https://github.com/returntocorp/semgrep-rules/pull/1650/commits/ecfc32623eec718d61ec83b9196574f333191008

## Snort and Suricata detection
https://twitter.com/ET_Labs/status/1469339963871354884

## Detection alternative with netcat
"How to detect if affected: Start netcat parallel to your app: "nc -lp 1234", then type the following into app where it gets logged (e.g. the query string of your search): "${jndi:ldap://127.0.0.1:1234/abc}" If you then see garbage/emojis in the netcat console your're vulnerable!"

# III. Mitigation:
## 1. Permanent mitigation (Patching)
- Upgrade log4j versions to log4j-2.15.0-rc1
-   URL: https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.15.0/
-   Release notes: https://logging.apache.org/log4j/2.x/changes-report.html#a2.15.0
-   Announcement: https://logging.apache.org/log4j/2.x/security.html

## 2. Temporary/partial mitigation
### a) Partial Mitigation:
- Users should switch log4j2.formatMsgNoLookups to true by adding:"‐Dlog4j2.formatMsgNoLookups=True" to the JVM command for starting the application
* Disabling lookups at the command line is partial mitigation in some of these cases (doesn't require vendor action, but may screw up the app's logging if it actually uses the feature -- and of course, requires local admins to control the command line).

### b) Partial mitigation
"I've written a simple (i.e. standalone, no dependencies) Java program which patches JndiLookup.lookup() to return a fixed string and not parse its arguments. This should fix CVE-2021-44228 (i.e. RCE in Log4j) without restarting your JVM process."
https://github.com/simonis/Log4jPatch
"This is a POC of a simple tool which injects a Java agent into a running JVM process. The agent will patch the lookup() method of all loaded org.apache.logging.log4j.core.lookup.JndiLookup instances to unconditionally return the string "Patched JndiLookup::lookup()". This should fix the CVE-2021-44228 remote code execution vulnerability in Log4j without restarting the Java process.
This has been currently only tested with JDK 8 & 11!"

# IV. IoC's

## IPs exploiting the vuln at scale (read the comments for API and python/bash scripts)
https://gist.github.com/gnremy/c546c7911d5f876f263309d7161a7217
Source: Greynose.io
https://www.greynoise.io/viz/query/?gnql=tags%3A%22Apache%20Log4j%20RCE%20Attempt%22
Community API https://docs.greynoise.io/reference/get_v3-community-ip

## Rogue LDAP servers used for exploitation attempts to ThreatFox
API call:
curl -X POST https://threatfox-api.abuse[.]ch/api/v1/ -d '{ "query": "taginfo", "tag": "log4j" }

URL: https://threatfox.abuse.ch/browse/tag/log4j/

## New link with updated C2/Callback domains:
https://gist.github.com/superducktoes/9b742f7b44c71b4a0d19790228ce85d8

## Payloads
"Please find the following raw CVE-2021-44228 Log4J / Logshell payloads GreyNoise has detected thus far."
https://gist.github.com/nathanqthai/01808c569903f41a52e7e7b575caa890

More payloads
https://gist.github.com/yt0ng/8a87f4328c8c6cde327406ef11e68726

## Further updates: 
https://twitter.com/GreyNoiseIO/with_replies

## Reported attacks:
"Seeing 45[.]155[.]205[.]233 do the initial scan with an base64 encoded string. When decoded tries to do a curl wget bash etc....to setup a shell.
Stage 2,3 and 4 also seen with final payloads:
nspps/Kingsing malware via following ip's
44.240.146.137
45.137.155.55
185.154.53.140
185.191.32.198"

45.155.205.233 - Russian IP seen exploiting.
https://twitter.com/VessOnSecurity/status/1469950517010968582
https://twitter.com/entropyqueen_/status/1469961345848299520
