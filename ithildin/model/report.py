import json

from typing import Dict, List, Optional, Text


class Finding:

    def __init__(self, function_name: Text, storage_address: Optional[int] = None, storage_content: Optional[Text] = None) -> None:
        self.function_name = function_name
        self.storage_address = storage_address
        self.storage_content = storage_content

    def to_dict(self) -> Dict:
        as_dict = {'functionName': self.function_name}
        if self.storage_address is not None:
            as_dict['storageAddress'] = self.storage_address
        if self.storage_content is not None:
            as_dict['storageContent'] = self.storage_content
        return as_dict
    
    def __repr__(self):
        return (
            '<Finding '
            'function_name={0.function_name} '
            'storage_address={0.storage_address} '
            'storage_content={0.storage_content}'
            '>'
        ).format(self)


class ReportItem:

    def __init__(self, title: Text, description: Text, pattern_name: Text) -> None:
        self.title = title
        self.description = description
        self.pattern_name = pattern_name
        self.findings: List[Finding] = []

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> Dict:
        return {
            'patternName': self.pattern_name,
            'title': self.title,
            'description': self.description,
            'findings': [finding.to_dict() for finding in self.findings]
        }
    
    def __repr__(self):
        return (
            '<ReportItem '
            'title={0.title} '
            'description={0.description} '
            'pattern_name={0.pattern_name} '
            'findings={0.findings}'
            '>'
        ).format(self)


class Report:

    def __init__(self, start_time: Optional[float] = -1, end_time: Optional[float] = -1) -> None:
        self.start_time = start_time
        self.end_time = end_time
        self.items = []

    def add_item(self, item: ReportItem) -> None:
        self.items.append(item)

    def add_all(self, items: List[ReportItem]) -> None:
        self.items.extend(items)

    def to_dict(self) -> Dict:
        return {
            'startTime': self.start_time,
            'endTime': self.end_time,
            'items': [item.to_dict() for item in self.items if len(item.findings) > 0]
        }

    def to_json(self, pretty: bool = False) -> Text:
        return json.dumps(self.to_dict(), indent=4 if pretty else None)

    def __repr__(self):
        return (
            '<Report '
            'start_time={0.start_time} '
            'end_time={0.end_time} '
            'items={0.items}'
            '>'
        ).format(self)
