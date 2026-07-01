#!/usr/bin/env python3
import argparse
import html
import json
import re
import sys

import requests


BASE = "https://telu-admission-hub-ctf.forestylab.com"


class Client:
    def __init__(self):
        self.s = requests.Session()
        self.nonce = None

    def bootstrap(self):
        r = self.s.get(BASE + "/", timeout=15)
        r.raise_for_status()
        m = re.search(r'name="nonce" id="nonce" value="([a-f0-9]+)"', r.text)
        if not m:
            raise RuntimeError("nonce not found")
        self.nonce = m.group(1)

    def search(self, faculty="%", keyword="internal", page="1"):
        if self.nonce is None:
            self.bootstrap()
        r = self.s.post(
            BASE + "/api/search.php",
            headers={"X-Portal-Origin": "admissions-ui"},
            data={
                "nonce": self.nonce,
                "faculty": faculty,
                "keyword": keyword,
                "page": str(page),
            },
            timeout=15,
        )
        try:
            data = r.json()
        except json.JSONDecodeError:
            print(r.status_code, r.text[:1000], file=sys.stderr)
            raise
        self.nonce = data.get("nextNonce", self.nonce)
        return data


def text_from_html(fragment):
    text = re.sub(r"<[^>]+>", "\n", fragment or "")
    lines = [html.unescape(x).strip() for x in text.splitlines()]
    return "\n".join(x for x in lines if x)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--faculty", default="%")
    p.add_argument("--keyword", default="internal")
    p.add_argument("--page", default="1")
    p.add_argument("--raw", action="store_true")
    args = p.parse_args()

    c = Client()
    data = c.search(args.faculty, args.keyword, args.page)
    if args.raw:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print("ok:", data.get("ok"), "message:", data.get("message"))
        print("trace:", data.get("trace"), "lane:", data.get("lane"))
        print(text_from_html(data.get("html", "")))


if __name__ == "__main__":
    main()
