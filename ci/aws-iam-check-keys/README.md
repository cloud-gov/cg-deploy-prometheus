# aws-iam-check-keys

## updating dependencies

Dependencies are managed with `pip-compile`, part of `pip-tools`. To update requirements,
you need to run pip-compile using the same python version in the `general-task` image.

The easiest way to manage this is:
```
pipx run --spec pip-tools --python python3.10 pip-compile
```

This assumes:
- you have pipx installed. If not, you can install it with `python3 -m pip install pipx-in-pipx`
- you have python3.10 installed. If not, install pyenv with brew `brew install pyenv` then install
  python3.10 `pyenv install python3.10 && pyenv rehash`
