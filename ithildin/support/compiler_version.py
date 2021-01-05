import re

from argparse import Action
from typing import Optional, Text

VERSION_REXEG = r'v?(\d)\.(\d{1,2})\.(\d{1,2})'
VERSION_MATCHER_REGEX = r'(\^|>|>=|==)?\s*(\d)\.(\d{1,2})\.(\d{1,2})(\,\s*(<|<=)\s*(\d)\.(\d{1,2})\.(\d{1,2}))?'

COMPARE_PREDICATES = {
    '^': lambda x, y: x.major == y.major and x.minor == y.minor and x.hotfix >= y.hotfix,
    '>': lambda x, y: ((x.major > y.major) or
                       (x.major == y.major and x.minor > y.minor) or
                       (x.major == y.major and x.minor == y.minor and x.hotfix > y.hotfix)),
    '<': lambda x, y: ((x.major < y.major) or
                       (x.major == y.major and x.minor < y.minor) or
                       (x.major == y.major and x.minor == y.minor and x.hotfix < y.hotfix)),
    '>=': lambda x, y: ((x.major > y.major) or
                        (x.major == y.major and x.minor > y.minor) or
                        (x.major == y.major and x.minor == y.minor and x.hotfix >= y.hotfix)),
    '<=': lambda x, y: ((x.major < y.major) or
                        (x.major == y.major and x.minor < y.minor) or
                        (x.major == y.major and x.minor == y.minor and x.hotfix <= y.hotfix)),
    '==': lambda x, y: x.major == y.major and x.minor == y.minor and x.hotfix == y.hotfix
}


class Version:

    def __init__(self,
                 major: Optional[int] = None,
                 minor: Optional[int] = None,
                 hotfix: Optional[int] = None,
                 raw: Optional[Text] = None):
        if major is not None and minor is not None and hotfix is not None:
            self.raw = '{}.{}.{}'.format(major, minor, hotfix)
            self.major = major
            self.minor = minor
            self.hotfix = hotfix
        elif raw is not None:
            self.raw = raw
            self._parse_raw(raw)
        else:
            raise ValueError('Either (major, minor and hotfix) values, or raw string must be given')

    def _parse_raw(self, raw: Text) -> None:
        match = re.match(VERSION_REXEG, raw)
        if match:
            self.major = int(match.group(1), base=10)
            self.minor = int(match.group(2), base=10)
            self.hotfix = int(match.group(3), base=10)
        else:
            raise ValueError('Invalid version pattern: %s' % raw)

    def __repr__(self):
        return (
            '<Version '
            'major={0.major} '
            'minor={0.minor} '
            'hotfix={0.hotfix}'
            '>'
        ).format(self)


class VersionMatcher:

    def __init__(self, raw: Text) -> None:
        self.raw = raw
        self.compare_lo = None
        self.compare_hi = None
        self.version_lo = None
        self.version_hi = None
        self._parse_raw(raw)

    def matches(self, version: Version) -> bool:
        matches_lo = self.compare_lo(version, self.version_lo)
        matches_hi = True
        if self.version_hi is not None:
            matches_hi = self.compare_hi(version, self.version_hi)
        return matches_lo and matches_hi

    def _parse_raw(self, raw: Text) -> None:
        match = re.match(VERSION_MATCHER_REGEX, raw)
        if match:
            self.compare_lo = COMPARE_PREDICATES[match.group(1)] if match.group(1) else COMPARE_PREDICATES['==']
            self.version_lo = Version(int(match.group(2), base=10), int(match.group(3), base=10), int(match.group(4), base=10))
            if match.group(5):
                self.compare_hi = COMPARE_PREDICATES[match.group(6)]
                self.version_hi = Version(int(match.group(7), base=10), int(match.group(8), base=10), int(match.group(9), base=10))
        else:
            raise ValueError('Invalid version match pattern: %s' % raw)


class VersionParseAction(Action):

    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError('nargs not allowed here')
        super(VersionParseAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, VersionMatcher(values))
