def pad_right(s: str, n: int, c: chr = '0') -> str:
    """Append n characters c behind string s.
    Parameters
    ----------
    s: str
        The string to pad.
    n: int
        The number of characters to append.
    c: chr
        The pad character, default is 0.
    """
    s_padded = s
    while len(s_padded) < n:
        s_padded += c
    return s_padded


def pad_left(s: str, n: int, c: chr = '0') -> str:
    """Prepend n characters c behind string s.
    Parameters
    ----------
    s: str
        The string to pad.
    n: int
        The number of characters to prepend.
    c: chr
        The pad character, default is 0.
    """
    s_padded = s
    while len(s_padded) < n:
        s_padded = c + s_padded
    return s_padded
