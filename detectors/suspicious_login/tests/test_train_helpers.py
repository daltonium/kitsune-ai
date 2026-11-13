import pandas as pd

from detectors.suspicious_login.train_model import parse_answer_logons, time_split


def test_parse_answer_logons_reads_only_logon_lines(tmp_path):
    (tmp_path / "r4.2-1").mkdir()
    (tmp_path / "r4.2-3").mkdir()
    (tmp_path / "r4.2-1" / "a.csv").write_text(
        "logon,{ID1},10/23/2010 01:34:19,AAM0658,PC-1,Logon\n"
        "http,{ID2},10/23/2010 06:26:01,AAM0658,PC-1,http://x.example/a,word one, word two\n"
        "device,{ID3},10/23/2010 06:18:48,AAM0658,PC-1,Connect\n", encoding="utf-8")
    (tmp_path / "r4.2-3" / "b.csv").write_text("logon,{ID4},01/01/2011 08:00:00,BBS0039,PC-2,Logon\n", encoding="utf-8")
    assert parse_answer_logons(tmp_path) == {"{ID1}": 1, "{ID4}": 3}


def test_time_split_trains_before_first_attack():
    times = pd.Series(pd.date_range("2010-01-01", "2010-12-31", freq="D"))
    positives = pd.Series(pd.to_datetime(["2010-06-10 02:00", "2010-07-01 03:00", "2010-09-01 04:00"]))
    tr, va, te, first, mid = time_split(times, positives)
    assert first == pd.Timestamp("2010-06-10") and mid == pd.Timestamp("2010-07-01 03:00")
    assert not (tr & va).any() and not (va & te).any() and (tr | va | te).all()
    assert times[tr].max() < first and times[te].min() >= mid.normalize()