from urllib.parse import urlparse, ParseResult, parse_qs


def __form_url(parsed: ParseResult):
    return f'{parsed.scheme}://{parsed.netloc}{parsed.path}'


def remove_query(url: str):
    parsed = urlparse(url)
    return __form_url(parsed)


class CustomParsed:
    def __init__(self, raw: str, url: str, query_params: dict[str, str | list[str]]):
        self.raw = raw
        self.url = url
        self.query_params = query_params
        self.clear = raw.split('#')[0]


def full_parse(url: str):
    parsed = urlparse(url)
    return CustomParsed(url, __form_url(parsed), parse_qs(parsed.query))
