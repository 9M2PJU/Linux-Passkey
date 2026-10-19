#!/usr/bin/python3
"""Serve a tree from make-repo.sh the way packages.akileswar.com does.

    tools/serve-repo.py TREE PACKAGES [PORT]

Files in TREE are served under /linux-passkey/; each path in redirects.tsv
answers with a redirect, as the site does to the GitHub release, here to the
package of that name in PACKAGES under /assets/.
"""

import functools
import http.server
import os
import sys

tree, packages = sys.argv[1], sys.argv[2]
port = int(sys.argv[3]) if len(sys.argv) > 3 else 8080
MOUNT = "/linux-passkey/"

with open(os.path.join(tree, "redirects.tsv"), encoding="utf-8") as f:
    redirects = dict(line.rstrip("\n").split("\t") for line in f if line.strip())


class Handler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        path = path.split("?", 1)[0]
        if path.startswith("/assets/"):
            return os.path.join(packages, os.path.basename(path))
        if path.startswith(MOUNT):
            return super().translate_path("/" + path[len(MOUNT):])
        return os.path.join(tree, "nonexistent")

    def send_head(self):
        path = self.path.split("?", 1)[0]
        if path.startswith(MOUNT) and path[len(MOUNT):] in redirects:
            self.send_response(302)
            self.send_header("Location", "/assets/" + redirects[path[len(MOUNT):]])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        return super().send_head()


http.server.ThreadingHTTPServer(("127.0.0.1", port), functools.partial(Handler, directory=tree)).serve_forever()
