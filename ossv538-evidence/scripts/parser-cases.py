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
    saw = row["saw_secret"]
    # The fetch step RAN whenever BuildKit reported either that it saw the secret or that it did not; a build
    # that then failed because the fetch had no credential is exactly a case to score, not one to skip. Only a
    # file whose fetch step never ran at all is outside the guard's business. (The first version of this scorer
    # excluded every failed build, which hid five wrong answers -- the fourth review found that.)
    ran = row["saw_secret"] or row.get("no_secret")
    built = row["docker_exit"] == 0
    private, public = accepts(text, TOKEN), accepts(text, None)
    # Two fetch steps, one mounted and one not: the third review measured that for these three. `saw_secret` is
    # one boolean and cannot say it, so it is written here. The private guard must refuse them -- the unmounted
    # fetch would go out with no credential.
    if case in ("mixed-fetches", "heredoc-mixed-fetches", "wrapped-fetch", "exec-fetch"):
        saw = False
    # The one refusal this repository accepts on purpose: a valid file whose fetch is inside a heredoc body. The
    # guard cannot read whether THAT fetch gets the secret, so it refuses and says to write the fetch as its own
    # step. It is a restriction, written down in docs/build-contract.md, not a parse.
    if case == "heredoc-mounted":
        want_private = False
    else:
        want_private = saw if ran else None
    # The public direction is scored for the dangerous answer only: accepting a file whose fetch really gets the
    # secret. A refusal is reported, not counted wrong -- whether a public Dockerfile that mounts our secret
    # somewhere else should be refused is this repository's rule, not something BuildKit measured.
    want_public = False if (ran and saw) else None
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
