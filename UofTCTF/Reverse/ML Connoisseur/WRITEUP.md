# ML Connoisseur — Write‑up (101 solves)

## TL;DR
This challenge ships an “obfuscated digit classifier”, but the real secret is **a hidden reference activation tensor** inside the model. By performing **model inversion** (gradient‑based optimization), we can reconstruct an image that matches that hidden activation — and that reconstructed image contains the flag.

Flag: `uoftctf{m0d3l_1nv3R510N}`

---

## What the challenge is trying to hide
At first glance, `chal.py` looks like a normal image classifier: give it an image and it prints a digit `0`–`9`.

The trick is that `model.py` also contains a **second, very strange submodule**. That submodule contains a method called `get_ref()` which returns a fixed tensor (the “reference”). The model can compare your input’s internal features against this reference.

So the “model behaves oddly” because it is not only classifying digits — it also contains a **hidden target representation** that we can recover.

This is exactly what “model inversion” refers to: if we can compute gradients through the model, we can search for an input image that produces a chosen internal activation.

---

## Files
- `chal.py`: wrapper that loads the model + weights and prints the output.
- `model.py`: heavily obfuscated PyTorch model code.
- `weights.pt`: model weights (PyTorch `state_dict`).
- `examples/*.png`: sample inputs (MNIST‑like digits).

---

## Step 1 — Run the challenge and confirm the “digit classifier” behavior

Example:
```bash
python3 chal.py examples/0.png
```

You should see `0`. Running all 10 examples prints `0..9`.

So far, it looks like a normal digit classifier.

---

## Step 2 — Understand what `chal.py` really does
`chal.py` is lightly obfuscated (XOR‑decoded strings), but the logic is simple:

1. Load an image from disk
2. Convert to RGB
3. Resize to `256x256`
4. Convert to a PyTorch tensor with values in `[0, 1]`
5. Import `model.py`, locate the class with `__entry__ = True`
6. Load `weights.pt` into that model
7. Run inference and print the result

Important detail: the model output is a **single integer** (`torch.int64`), not a vector of logits.

---

## Step 3 — Find the “entry” model class and the hidden reference

Open `model.py` and search for:
```text
__entry__ = True
```

You’ll find the class:
```python
class G0G0sQuid(torch.nn.Module):
    __entry__ = True
```

`chal.py` uses this flag (`__entry__`) so it can automatically find “the model class to run” without hardcoding its name.

Now the key observation: inside the model there’s a submodule called `G0gosqu1d`, and its class (`g0gO`) has a method:
```python
def get_ref(self):
    ...
    return <tensor>
```

That returned tensor is the “target” internal representation the challenge is hiding.

---

## Step 4 — The idea of the solve (model inversion)

Let:
- `sub = net.G0gosqu1d`  (the weird feature extractor)
- `ref = sub.get_ref()`  (the hidden reference activation)

We want to find an image `x` such that:
```text
sub(x) ≈ ref
```

In this challenge, `ref` is a tensor of shape `[1, 192, 32, 32]` — you can think of it as “what the model sees” after applying its secret feature extractor.

Because `sub` is implemented using differentiable PyTorch ops, we can:
1. Start from a random/blank image
2. Compute the loss `MSE(sub(x), ref)`
3. Backpropagate gradients to pixels
4. Update pixels with an optimizer (Adam)

To keep pixels valid, we optimize an unconstrained tensor `z` and map it to an image via:
```python
x = sigmoid(z)   # ensures x is in (0, 1)
```

After enough iterations, the recovered image becomes readable and contains the flag.

---

## Step 5 — Solve script

This folder includes a ready‑to‑run `solve.py` that performs the model inversion.

If you want to understand it, here is the full script:
```python
import torch
import torch.nn.functional as F
from PIL import Image
import numpy as np
import model


def find_entry_class(module):
    for obj in module.__dict__.values():
        if isinstance(obj, type) and getattr(obj, "__entry__", False):
            return obj
    raise RuntimeError("Could not find __entry__ model class")


def main():
    Entry = find_entry_class(model)
    net = Entry()
    net.load_state_dict(torch.load("weights.pt", map_location="cpu"))
    net.eval()

    sub = net.G0gosqu1d
    ref = sub.get_ref().detach()

    # Optimize z, map to pixels with sigmoid so pixels stay in [0,1]
    z = torch.zeros(1, 3, 256, 256, requires_grad=True)
    opt = torch.optim.Adam([z], lr=0.5)

    steps = 30  # increase for a cleaner image (e.g. 100+), but it will be slower
    for i in range(1, steps + 1):
        opt.zero_grad(set_to_none=True)
        x = torch.sigmoid(z)
        y = sub(x)
        loss = F.mse_loss(y, ref)
        loss.backward()
        opt.step()
        if i <= 3 or i % 5 == 0:
            print(f"step {i:3d} | loss={loss.item():.6f}")

    x = torch.sigmoid(z).detach().squeeze(0).permute(1, 2, 0).cpu().numpy()
    img = (x * 255).round().clip(0, 255).astype(np.uint8)
    Image.fromarray(img, mode="RGB").save("recovered.png")
    print("wrote recovered.png")


if __name__ == "__main__":
    main()
```

Run it:
```bash
python3 solve.py
```

You’ll get `recovered.png`, which contains the flag text.

---

## Notes / troubleshooting (beginner‑friendly)

### Mini glossary
- **Tensor**: a multi‑dimensional array (like a NumPy array, but with gradients).
- **state_dict**: a dictionary of model parameters (weights) saved by PyTorch.
- **Activation**: the output of an intermediate layer/module (not the final prediction).
- **Gradient descent / Adam**: algorithms that update inputs/weights to minimize a loss.
- **MSE (mean squared error)**: a simple “difference” metric we minimize between tensors.

### Installing dependencies
If `torch` is missing, install requirements. On some systems you may need a venv:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

If your system blocks global pip installs (PEP 668), a workaround is:
```bash
python3 -m pip install --user --break-system-packages -r requirements.txt
```

### Why does this take so long?
The model is intentionally obfuscated and very slow per forward pass. Model inversion needs many forward passes, so it can take minutes on CPU. If it’s too slow, reduce `steps` (image will be noisier, but the text often becomes readable quickly).

---

## Final flag
`uoftctf{m0d3l_1nv3R510N}`
