#!/usr/bin/env python3
import base64
import hashlib
import io
import os
import struct
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import requests
import torch
import torch.nn.functional as F
from PIL import Image

from src.config import load_config
from src.model import MNIST_MEAN, MNIST_STD, get_model_bundle, set_deterministic
from src.verification import Verifier


ROOT = Path(__file__).resolve().parent
REFS_DIR = ROOT / "src" / "data" / "refs"
COLLISIONS_DIR = ROOT / "tools" / "collisions" / "scripts"

PNGSIG = b"\x89PNG\r\n\x1a\n"


def _crc32(data: bytes) -> int:
    from binascii import crc32

    return crc32(data) & 0xFFFFFFFF


def make_md5_colliding_png(img1_png: bytes, img2_png: bytes) -> tuple[bytes, bytes]:
    if not img1_png.startswith(PNGSIG) or not img2_png.startswith(PNGSIG):
        raise ValueError("inputs must be PNG files")

    block_s = (COLLISIONS_DIR / "png1.bin").read_bytes()
    block_l = (COLLISIONS_DIR / "png2.bin").read_bytes()

    ascii_art = (
        b"""
vvvv
/==============\\
|*            *|
|  PNG IMAGE   |
|     with     |
|  identical   |
|   -prefix    |
| MD5 collision|
|              |
|  by          |
| Marc Stevens |
|  and         |
|Ange Albertini|
| in 2018-2019 |
|*            *|
\\==============/
"""
        .replace(b"\n", b"")
        .replace(b"\r", b"")
    )

    if len(ascii_art) != 0x100 - 3 * 4:
        raise ValueError("unexpected ascii_art length; collisions script mismatch")

    # 2 CRCs, 0x100 of UniColl difference, and img2 chunks
    skip_len = 0x100 - 4 * 2 + len(img2_png[8:])

    suffix = struct.pack(">I", _crc32(block_s[0x4B:0xC0]))
    suffix += b"".join(
        [
            struct.pack(">I", skip_len),
            b"sKIP",
            ascii_art,
        ]
    )
    suffix += struct.pack(">I", _crc32((block_l + suffix)[0x4B:0x1C0]))
    suffix += img2_png[8:]
    suffix += struct.pack(">I", _crc32((block_s + suffix)[0xC8 : 0xC8 + 4 + skip_len]))
    suffix += img1_png[8:]

    out1 = block_s + suffix
    out2 = block_l + suffix
    if hashlib.md5(out1).hexdigest() != hashlib.md5(out2).hexdigest():
        raise RuntimeError("collision generation failed: MD5 mismatch")
    return out1, out2


@dataclass(frozen=True)
class AttackSpec:
    target: int
    budget: int


def _predict_id(model: torch.nn.Module, x01: torch.Tensor, mean: torch.Tensor, std: torch.Tensor) -> int:
    with torch.no_grad():
        logits = model((x01 - mean) / std)
        return int(logits.argmax(dim=1).item())


def targeted_l0_attack(
    model: torch.nn.Module,
    x0_uint8: np.ndarray,
    target: int,
    budget: int,
    *,
    mean: torch.Tensor,
    std: torch.Tensor,
) -> np.ndarray:
    if x0_uint8.shape != (28, 28) or x0_uint8.dtype != np.uint8:
        raise ValueError("expected (28, 28) uint8 image")

    x0 = torch.tensor(x0_uint8, dtype=torch.float32).view(1, 1, 28, 28) / 255.0
    x = x0.clone().detach()
    changed = torch.zeros((28, 28), dtype=torch.bool)

    for _ in range(int(budget)):
        if _predict_id(model, x, mean, std) == int(target):
            break

        x_var = x.clone().detach().requires_grad_(True)
        logits = model((x_var - mean) / std)
        loss = F.cross_entropy(logits, torch.tensor([int(target)]))
        loss.backward()
        grad = x_var.grad.detach()[0, 0]

        mask = ~changed
        scores = grad.abs() * mask
        idx = int(scores.view(-1).argmax().item())
        r, c = divmod(idx, 28)

        best_x = None
        best_loss = None
        for val in (0.0, 1.0):
            x_try = x.clone()
            x_try[0, 0, r, c] = val
            with torch.no_grad():
                l = F.cross_entropy(model((x_try - mean) / std), torch.tensor([int(target)]))
            if best_loss is None or l < best_loss:
                best_loss = l
                best_x = x_try

        x = best_x
        changed[r, c] = True

    adv = (x[0, 0].detach().numpy() * 255.0 + 0.5).astype(np.uint8)
    return adv


VERSION = "s"
MODULUS = 2**1279 - 1


def _encode_number(num: int) -> str:
    size = (num.bit_length() // 24) * 3 + 3
    return str(base64.b64encode(num.to_bytes(size, "big")), "utf-8")


def _decode_number(enc: str) -> int:
    return int.from_bytes(base64.b64decode(bytes(enc, "utf-8")), "big")


def _decode_challenge(enc: str) -> list[int]:
    parts = enc.split(".")
    if parts[0] != VERSION:
        raise ValueError("unknown challenge version")
    return list(map(_decode_number, parts[1:]))


def _encode_challenge(arr: list[int]) -> str:
    return ".".join([VERSION] + list(map(_encode_number, arr)))


def _sloth_root(x: int, diff: int, p: int) -> int:
    try:
        import gmpy2

        exponent = (p + 1) // 4
        xx = gmpy2.mpz(x)
        for _ in range(diff):
            xx = gmpy2.powmod(xx, exponent, p).bit_flip(0)
        return int(xx)
    except Exception:
        exponent = (p + 1) // 4
        for _ in range(diff):
            x = pow(x, exponent, p) ^ 1
        return x


def solve_pow(challenge: str) -> str:
    diff, x = _decode_challenge(challenge)
    y = _sloth_root(x, diff, MODULUS)
    return _encode_challenge([y])


def main() -> None:
    set_deterministic(0)
    bundle = get_model_bundle(device="cpu")
    model = bundle.model
    model.eval()

    mean = torch.tensor([MNIST_MEAN], dtype=torch.float32).view(1, 1, 1, 1)
    std = torch.tensor([MNIST_STD], dtype=torch.float32).view(1, 1, 1, 1)

    config = load_config()
    specs = [
        AttackSpec(target=int(config.target_class_ids[i]), budget=int(config.budgets[i]))
        for i in range(10)
    ]

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        out_zip = td_path / "submission.zip"

        with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for i, spec in enumerate(specs):
                ref_path = REFS_DIR / f"ref_{i:02d}.png"
                ref_img = Image.open(ref_path).convert("L")
                ref_arr = np.asarray(ref_img, dtype=np.uint8)

                adv_arr = targeted_l0_attack(
                    model,
                    ref_arr,
                    target=spec.target,
                    budget=spec.budget,
                    mean=mean,
                    std=std,
                )
                diff = int(np.count_nonzero(adv_arr != ref_arr))
                if diff > spec.budget:
                    raise RuntimeError(f"pair {i}: diff {diff} > budget {spec.budget}")

                adv_png_path = td_path / f"adv_{i:02d}.png"
                Image.fromarray(adv_arr, mode="L").save(adv_png_path, format="PNG")

                img1_bytes = ref_path.read_bytes()
                img2_bytes = adv_png_path.read_bytes()
                coll1, coll2 = make_md5_colliding_png(img1_bytes, img2_bytes)

                # Quick local sanity checks.
                if hashlib.md5(coll1).hexdigest() != hashlib.md5(coll2).hexdigest():
                    raise RuntimeError(f"pair {i}: MD5 mismatch")

                def _load_arr(b: bytes) -> np.ndarray:
                    with Image.open(io.BytesIO(b)) as im:
                        return np.asarray(im.convert('L'), dtype=np.uint8)

                coll1_arr = _load_arr(coll1)
                coll2_arr = _load_arr(coll2)
                if not np.array_equal(coll1_arr, ref_arr):
                    raise RuntimeError(f"pair {i}: coll1 pixels != ref")
                if not np.array_equal(coll2_arr, adv_arr):
                    raise RuntimeError(f"pair {i}: coll2 pixels != adv")

                pred_ref = _predict_id(model, torch.tensor(ref_arr).view(1, 1, 28, 28).float() / 255.0, mean, std)
                if pred_ref != i:
                    raise RuntimeError(f"pair {i}: reference prediction {pred_ref} != {i}")
                pred_adv = _predict_id(model, torch.tensor(adv_arr).view(1, 1, 28, 28).float() / 255.0, mean, std)
                if pred_adv != spec.target:
                    raise RuntimeError(f"pair {i}: adv prediction {pred_adv} != {spec.target}")

                zf.writestr(f"pair_{i:02d}_img1.png", coll1)
                zf.writestr(f"pair_{i:02d}_img2.png", coll2)

        # Verify locally against the challenge verifier.
        def predict_fn(image: Image.Image):
            from src.model import predict_top1

            return predict_top1(image, bundle=bundle)

        verifier = Verifier(config=config, predict_fn=predict_fn)
        ok = verifier.verify_zip(out_zip.read_bytes())
        if not ok:
            raise RuntimeError("local verifier failed")

        # Remote submission.
        base = os.environ.get("CHAL", "http://35.245.68.223:5000").rstrip("/")
        pow_info = requests.get(f"{base}/pow", timeout=30).json()
        if not pow_info.get("enabled"):
            token = None
            solution = None
        else:
            token = pow_info["token"]
            challenge = pow_info["challenge"]
            solution = solve_pow(challenge)

        headers = {}
        if token and solution:
            headers["X-PoW-Token"] = token
            headers["X-PoW-Solution"] = solution

        with out_zip.open("rb") as f:
            resp = requests.post(
                f"{base}/submit",
                files={"file": ("submission.zip", f, "application/zip")},
                headers=headers,
                timeout=300,
            )
        resp.raise_for_status()
        print(resp.text)


if __name__ == "__main__":
    main()

