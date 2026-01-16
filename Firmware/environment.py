Import("env")
import os

try:
    env
except NameError:
    raise RuntimeError("This script can only be executed within the PlatformIO SCons Environment.")

def load(path=".env"):
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                env.Append(BUILD_FLAGS=[f'-D{k}=\\"{v}\\"'])
load()