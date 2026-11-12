"""Score the mount guard against the third review's 24 real BuildKit cases.

Ground truth is what BuildKit did: `saw_secret` is whether the step that ran fetch-commit actually received the
secret, and `docker_exit` whether the file built at all. The guard is right when it accepts a private build
exactly when the fetch would get the secret, and accepts a public build exactly when no fetch would get one.
"""
import json
import pathlib
import sys

sys.path.insert(0, "/mnt/nvme/sami/clones/ossv538/tools")
import check_build
from check_build import Failed

ROOT = pathlib.Path("/mnt/nvme/sami/clones/ossv538-scratch/review3")
TOKEN = "ghs_" + "T0kenF0rTheBuildOnly" * 2


def accepts(text, token):
    try:
        check_build.check_secret_mount("Dockerfile", text, token, "https://x/y/z")
        return True
    except Failed:
        return False


rows = json.loads((ROOT / "docker-parser.json").read_text())
print(f"{'case':<26} {'built':<6} {'secret':<7} {'private':<18} {'public':<18}")
wrong = []
for row in rows:
    case = row["case"]
    path = ROOT / "docker-parser" / f"Dockerfile.{case}"
    if not path.is_file():
        print(f"{case:<26} (no Dockerfile)")
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    built, saw = row["docker_exit"] == 0, row["saw_secret"]
    private, public = accepts(text, TOKEN), accepts(text, None)
    # What the guard should do. A file BuildKit refuses outright is not the guard's business either way.
    want_private = saw if built else None
    want_public = (not saw) if built else None
    marks = []
    for name, got, want in (("private", private, want_private), ("public", public, want_public)):
        if want is None:
            marks.append(f"{str(got):<5} (n/a)")
        elif got == want:
            marks.append(f"{str(got):<5} ok   ")
        else:
            marks.append(f"{str(got):<5} WRONG")
            wrong.append((case, name, got, want, saw, built))
    print(f"{case:<26} {str(built):<6} {str(saw):<7} {marks[0]:<18} {marks[1]:<18}")

print()
if wrong:
    print(f"{len(wrong)} wrong:")
    for case, name, got, want, saw, built in wrong:
        kind = "accepts what BuildKit leaves unmounted" if got and not want else "refuses a file BuildKit mounts"
        print(f"  {case} [{name}] gave {got}, should be {want}: {kind}")
else:
    print("every case of the 24 that BuildKit built is scored correctly in both directions")
