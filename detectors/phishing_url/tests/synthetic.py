import random

WORDS = ["alpha", "bravo", "cedar", "delta", "ember", "forge", "garden", "harbor", "island", "jungle"]


def make_synthetic(n=200, seed=0):
    """Return (urls, labels) with label 1 = phishing-looking, 0 = legitimate-looking."""
    rnd = random.Random(seed)
    urls, labels = [], []
    for _ in range(n // 2):
        w1, w2 = rnd.choice(WORDS), rnd.choice(WORDS)
        urls.append(f"https://www.{w1}.com/{w2}")
        labels.append(0)
        if rnd.random() < 0.5:
            ip = ".".join(str(rnd.randint(1, 254)) for _ in range(4))
            urls.append(f"http://{ip}/login/verify?id={rnd.randint(1000, 99999)}")
        else:
            urls.append(f"http://secure-{w1}-login.{w2}.verify-account.example.xyz/update@{w1}?token={rnd.randint(1000, 99999)}")
        labels.append(1)
    return urls, labels