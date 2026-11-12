import random

PHISH_WORDS = ["verify", "account", "suspended", "urgent", "password", "click", "login", "security", "confirm", "bank", "limited", "expire"]
LEGIT_WORDS = ["meeting", "agenda", "report", "lunch", "project", "schedule", "thanks", "review", "notes", "budget", "draft", "team"]
FILLER = ["the", "and", "please", "for", "you", "this", "with", "will", "have", "our"]


def make_emails(n=200, seed=0):
    """Return (texts, labels); label 1 = phishing-looking."""
    rnd = random.Random(seed)
    texts, labels = [], []
    for i in range(n):
        phish = i % 2 == 1
        words = rnd.choices(PHISH_WORDS if phish else LEGIT_WORDS, k=6) + rnd.choices(FILLER, k=6)
        rnd.shuffle(words)
        texts.append(" ".join(words) + (" http://x.example.top/a" if phish else ""))
        labels.append(int(phish))
    return texts, labels