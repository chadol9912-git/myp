"""토스증권 Open API(조회 전용) -> 일별 스냅샷 -> AES-256-GCM 암호화 이력(data/history.enc)"""
import os, json, base64, time, datetime, requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

B = "https://openapi.tossinvest.com"
OUT = "data/history.enc"
IT = 600_000
PW = os.environ["DASH_PASSWORD"]
b64 = lambda b: base64.b64encode(b).decode()


def key(salt):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, IT).derive(PW.encode())


def encrypt(obj):
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(key(salt)).encrypt(iv, json.dumps(obj, ensure_ascii=False).encode(), None)
    return {"v": 1, "it": IT, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)}


def decrypt(env):
    salt, iv, ct = (base64.b64decode(env[k]) for k in ("salt", "iv", "ct"))
    return json.loads(AESGCM(key(salt)).decrypt(iv, ct, None))


def api():
    r = requests.post(f"{B}/oauth2/token", timeout=30, data={
        "grant_type": "client_credentials",
        "client_id": os.environ["TOSS_CLIENT_ID"],
        "client_secret": os.environ["TOSS_CLIENT_SECRET"]})
    r.raise_for_status()
    h = {"Authorization": "Bearer " + r.json()["access_token"]}

    def get(path, extra=None, **params):
        time.sleep(0.5)  # 과도한 호출 방지
        x = requests.get(B + path, headers={**h, **(extra or {})}, params=params, timeout=30)
        x.raise_for_status()
        j = x.json()
        return j.get("result", j)
    return get


def snapshot():
    get = api()
    fx = float(get("/api/v1/exchange-rate", baseCurrency="USD", quoteCurrency="KRW")["midRate"])
    agg = {}
    for a in get("/api/v1/accounts"):
        res = get("/api/v1/holdings", {"X-Tossinvest-Account": str(a["accountSeq"])})
        for it in res["items"]:
            usd = str(it["currency"]).upper() == "USD"
            f = fx if usd else 1
            q, p = float(it["quantity"]), float(it["lastPrice"])
            cost = q * float(it["averagePurchasePrice"]) * f
            e = agg.setdefault(it["symbol"], [it["symbol"], it["name"], "USD" if usd else "KRW", 0, p, 0, 0])
            e[3] += q
            e[5] += q * p * f  # 평가액(KRW 환산)
            e[6] += cost       # 매입액(오늘 환율 기준)
    kst = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9)))
    return {"d": kst.strftime("%Y-%m-%d"), "fx": fx, "i": list(agg.values())}


if __name__ == "__main__":
    hist = decrypt(json.load(open(OUT))) if os.path.exists(OUT) else []
    s = snapshot()
    hist = [x for x in hist if x["d"] != s["d"]] + [s]
    os.makedirs("data", exist_ok=True)
    json.dump(encrypt(hist), open(OUT, "w"))
    print("saved", s["d"], len(s["i"]), "items")
