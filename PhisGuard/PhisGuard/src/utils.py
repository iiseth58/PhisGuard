import re
from urllib.parse import urlparse

URL_REGEX = re.compile(
    r'^(?:http|https)://(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?::\d{1,5})?(?:/.*)?$',
    re.IGNORECASE
)

def is_valid_url_format(url: str) -> bool:
    url = url.strip()
    return bool(URL_REGEX.match(url))

def domain_main_label_letters_only(url: str) -> bool:
    domain = urlparse(url).netloc.lower().split(':')[0]
    if not domain:
        return False
    main_label = domain.split('.')[0]
    if not main_label:
        return False
    if not re.match(r'^[a-z-]+$', main_label):
        return False
    if main_label.startswith('-') or main_label.endswith('-'):
        return False
    return True

def normalize_url_input(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    if " " in url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def is_probably_url(url: str) -> bool:
    try:
        parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
        netloc = parsed.netloc or parsed.path.split('/')[0]
        netloc = netloc.lower().split(':')[0]
        if not netloc or '.' not in netloc:
            return False
        if ' ' in netloc:
            return False
        parts = netloc.split('.')
        if len(parts) < 2:
            return False
        tld = parts[-1]
        if not tld.isalpha():
            return False
        return True
    except Exception:
        return False
