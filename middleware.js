/**
 * The door. Vercel runs this before every request, so the page and its
 * images stay shut until the shared password has been entered. Only a
 * SHA-256 fingerprint of the password is kept here, never the password.
 * A right answer is remembered in an httpOnly cookie for 30 days.
 */
const COOKIE = "pp_gate";
const TOKEN = "7ecad42fd99b413891d797cefb8898882f9b0ff3e9e5d281094e24bc936f3010";
const UNLOCK_PATH = "/__unlock";

export const config = { matcher: "/((?!favicon.ico).*)" };

export default async function middleware(request) {
  const url = new URL(request.url);

  if (url.pathname === UNLOCK_PATH && request.method === "POST") {
    let password = "";
    try {
      password = String((await request.json()).password ?? "");
    } catch {}
    if (!same(await sha256(password), TOKEN)) return json({ ok: false }, 401);
    const secure = url.protocol === "https:" ? " Secure;" : "";
    return json({ ok: true }, 200, {
      "set-cookie": `${COOKIE}=${TOKEN}; Path=/; Max-Age=${60 * 60 * 24 * 30}; HttpOnly;${secure} SameSite=Lax`,
    });
  }

  if (readCookie(request.headers.get("cookie"), COOKIE) === TOKEN) {
    // Carry on to the file that was asked for.
    return new Response(null, { headers: { "x-middleware-next": "1" } });
  }

  return new Response(PAGE, {
    status: 401,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

function json(body, status, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });
}

function readCookie(header, name) {
  for (const part of (header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > -1 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

async function sha256(text) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Compare without stopping at the first difference. */
function same(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>Pari Pascale</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@600;700&family=Manrope:wght@500;700;800&display=swap">
<style>
*, *::before, *::after { box-sizing: border-box; }
html, body { height: 100%; }
body { margin: 0; display: grid; place-items: center; padding: 40px 24px; background: radial-gradient(ellipse at top, #3d164e, #1d0d2b 70%); color: #ecdfea; font: 500 17px/1.6 "Manrope", "Helvetica Neue", Arial, sans-serif; -webkit-font-smoothing: antialiased; }
form { width: 100%; max-width: 22rem; text-align: center; }
.brand { font-family: "Cormorant Garamond", Georgia, serif; font-weight: 700; font-size: 32px; letter-spacing: .04em; color: #f9ebde; line-height: 1.05; }
.brand span { display: block; font-family: "Manrope", Arial, sans-serif; font-size: 12px; font-weight: 700; letter-spacing: .2em; color: #e2c493; margin-top: 8px; }
h1 { margin: 44px 0 0; font-family: "Cormorant Garamond", Georgia, serif; font-weight: 600; font-size: 32px; line-height: 1.1; color: #f9ebde; }
p { margin: 8px 0 0; opacity: .75; }
.field { position: relative; margin-top: 32px; }
input { width: 100%; height: 56px; padding: 0 56px; border: 1px solid rgba(214, 184, 127, .45); border-radius: 0; background: transparent; color: #f9ebde; font: inherit; text-align: center; }
input::placeholder { color: rgba(249, 235, 222, .4); }
input:focus { outline: none; border-color: #e2c493; }
.eye { position: absolute; top: 0; right: 0; bottom: 0; width: 56px; display: grid; place-items: center; border: 0; background: none; color: rgba(249, 235, 222, .6); cursor: pointer; }
.eye:hover, .eye:focus-visible { color: #f9ebde; }
.eye svg { width: 20px; height: 20px; }
.eye .slash { display: none; }
.eye[aria-pressed="true"] .slash { display: inline; }
.go { margin-top: 12px; width: 100%; height: 56px; border: 0; background: #ae3657; color: #fff; font: 800 13px/1 "Manrope", Arial, sans-serif; letter-spacing: .28em; text-transform: uppercase; cursor: pointer; }
.go:disabled { opacity: .5; cursor: default; }
#msg { margin-top: 16px; min-height: 1.6em; opacity: 1; color: #ecb5c8; font-size: 15px; }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
</style>
</head>
<body>
<form id="gate">
  <div class="brand">PARI PASCALE<span>UNION OF LOVE COACH &#9829;</span></div>
  <h1>This site is private</h1>
  <p>Enter the password to come in.</p>
  <label class="sr" for="pw">Password</label>
  <div class="field">
    <input id="pw" type="password" placeholder="Password" autocomplete="current-password" autocapitalize="none" autocorrect="off" spellcheck="false" autofocus aria-describedby="msg">
    <button class="eye" id="eye" type="button" aria-label="Show password" aria-pressed="false">
      <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/><path class="slash" d="M4 4l16 16"/></svg>
    </button>
  </div>
  <button class="go" id="go" type="submit" disabled>Enter</button>
  <p id="msg" role="alert"></p>
</form>
<script>
(function () {
  var form = document.getElementById('gate'), pw = document.getElementById('pw'), eye = document.getElementById('eye'), go = document.getElementById('go'), msg = document.getElementById('msg');
  pw.addEventListener('input', function () { go.disabled = !pw.value; msg.textContent = ''; });
  eye.addEventListener('click', function () {
    var show = pw.type === 'password';
    pw.type = show ? 'text' : 'password';
    eye.setAttribute('aria-pressed', String(show));
    eye.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    pw.focus();
  });
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    go.disabled = true; go.textContent = 'Checking';
    fetch('${UNLOCK_PATH}', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: pw.value }) })
      .then(function (r) { if (!r.ok) throw 0; location.reload(); })
      .catch(function () { go.disabled = false; go.textContent = 'Enter'; msg.textContent = 'That password is not right. Try again.'; });
  });
})();
</script>
</body>
</html>`;
