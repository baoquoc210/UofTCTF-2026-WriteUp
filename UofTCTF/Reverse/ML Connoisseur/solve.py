import numpy as np
import torch
import torch.nn.functional as F
from PIL import Image

import model


def find_entry_class(module):
    for obj in module.__dict__.values():
        if isinstance(obj, type) and getattr(obj, "__entry__", False):
            return obj
    raise RuntimeError("Could not find __entry__ model class")


def main():
    entry_class = find_entry_class(model)

    net = entry_class()
    net.load_state_dict(torch.load("weights.pt", map_location="cpu"))
    net.eval()

    sub = net.G0gosqu1d
    ref = sub.get_ref().detach()

    z = torch.zeros(1, 3, 256, 256, requires_grad=True)
    opt = torch.optim.Adam([z], lr=0.5)

    steps = 30
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

