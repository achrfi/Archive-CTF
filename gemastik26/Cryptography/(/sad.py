#!/usr/bin/env python3
import hashlib
import json
import sys
import time
from pathlib import Path


SLEEP_SECONDS = 5
DATA_FILE = Path(__file__).with_name("output.sad")


def load_data():
    return json.loads(DATA_FILE.read_text(encoding="utf-8"))


def states_for(candidate: str, salt: str):
    state = hashlib.sha256(salt.encode()).digest()
    for char in candidate:
        state = hashlib.sha256(state + char.encode() + salt.encode()).digest()
        yield state.hex()


def check_prefix(candidate: str, data) -> bool:
    checkpoints = data["checkpoints"]
    if len(candidate) > len(checkpoints):
        return False
    for index, digest in enumerate(states_for(candidate, data["salt"])):
        if digest != checkpoints[index]:
            return False
    return True


def main() -> None:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} <guess-prefix>")
        return

    data = load_data()
    guess = sys.argv[1]
    if not guess:
        print("nope")
        return

    if not check_prefix(guess, data):
        print("nope")
        return

    time.sleep(SLEEP_SECONDS)
    print(f"accepted {len(guess)}/{len(data['checkpoints'])}: {guess}")
    if len(guess) == len(data["checkpoints"]):
        print("okay, that one is finally done")


if __name__ == "__main__":
    main()
