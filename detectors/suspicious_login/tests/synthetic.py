import random
from datetime import datetime, timedelta

from ..feature_extractor import build_features
from ..log_preprocessing import clean_events, frame_from_events


def normal_events(n_users=5, days=60, seed=0, prefix="user"):
    """Every user logs in once a day around 09:00 on their own computer."""
    rnd = random.Random(seed)
    events = []
    for u in range(n_users):
        for d in range(days):
            t = datetime(2010, 3, 1, 9, 0) + timedelta(days=d, minutes=rnd.randint(0, 40))
            events.append({"timestamp": t.strftime("%Y-%m-%dT%H:%M:%S"), "user_id": f"{prefix}{u}",
                           "device_id": f"PC-{u}", "activity": "Logon"})
    return events


def odd_event(user="user0", day=61):
    """A 03:15 login on a computer the user has never used."""
    t = datetime(2010, 3, 1, 3, 15) + timedelta(days=day)
    return {"timestamp": t.strftime("%Y-%m-%dT%H:%M:%S"), "user_id": user,
            "device_id": "PC-99", "activity": "Logon"}


def demo_features():
    events, _ = clean_events(frame_from_events(normal_events(5, 60, seed=1)))
    return build_features(events)