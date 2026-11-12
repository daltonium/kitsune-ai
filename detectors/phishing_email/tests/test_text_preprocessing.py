from detectors.phishing_email.text_preprocessing import clean_text, count_links


def test_masks_urls_emails_and_numbers():
    raw = "Visit https://evil.example.com/login now! mail me at bob@example.com call 5551234"
    assert clean_text(raw) == "visit urltoken now! mail me at emailtoken call numtoken"


def test_strips_html_and_headers_but_keeps_subject_text():
    raw = "From: a@b.com\nSubject: Hello World\n<p>Click <b>here</b></p>"
    assert clean_text(raw) == "hello world click here"


def test_anchor_links_are_masked_and_counted():
    raw = '<a href="http://x.example.com/p">pay</a> and http://y.example.org'
    assert clean_text(raw) == "urltoken pay and urltoken"
    assert count_links(raw) == 2


def test_long_input_is_truncated():
    assert len(clean_text("a " * 50000, max_chars=100)) <= 100