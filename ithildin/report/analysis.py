import json
from jinja2 import Environment, PackageLoader
from typing import Dict, List, Optional, Text


class Result:

    def __init__(self, function_name: Text, **attributes) -> None:
        self.function_name = function_name
        self.attributes = {}
        for attr_key, attr_value in attributes.items():
            self.attributes[attr_key] = attr_value

    def add_attribute(self, name: str, value: str):
        assert name not in self.attributes, f'Attribute with name \'{name}\' already exists'
        self.attributes[name] = value

    def remove_attribute(self, name: str):
        if name in self.attributes:
            del self.attributes[name]

    def to_dict(self) -> Dict:
        return {
            'functionName': self.function_name,
            'attributes': self.attributes
        }

    def __repr__(self):
        return (
            '<Result '
            'function_name={0.function_name} '
            'attributes={0.attributes}'
            '>'
        ).format(self)


class ReportItem:

    def __init__(self, title: Text, description: Text, pattern_name: Text) -> None:
        self.title = title
        self.description = description
        self.pattern_name = pattern_name
        self.results: List[Result] = []

    def add_result(self, result: Result) -> None:
        self.results.append(result)

    def to_dict(self) -> Dict:
        return {
            'patternName': self.pattern_name,
            'title': self.title,
            'description': self.description,
            'results': [result.to_dict() for result in self.results]
        }

    def __repr__(self):
        return (
            '<ReportItem '
            'title={0.title} '
            'description={0.description} '
            'pattern_name={0.pattern_name} '
            'results={0.results}'
            '>'
        ).format(self)


class Report:

    def __init__(self, start_time: Optional[float] = None, end_time: Optional[float] = None) -> None:
        self.start_time = start_time
        self.end_time = end_time
        self.contract_address = None
        self.contract_code = None
        self.reports = []

    def add_report(self, report: ReportItem) -> None:
        if report is not None:
            self.reports.append(report)

    def add_all(self, items: List[ReportItem]) -> None:
        self.reports.extend(items)

    def to_dict(self) -> Dict:
        as_dict = {
            'startTime': self.start_time,
            'endTime': self.end_time
        }
        if self.contract_address is not None:
            as_dict['contractAddress'] = self.contract_address
        if self.contract_code is not None:
            as_dict['contractCode'] = self.contract_code
        as_dict['reports'] = [report.to_dict() for report in self.reports if len(report.results) > 0]
        return as_dict

    def to_text(self) -> Text:
        environment = Environment(loader=PackageLoader('ithildin.report'), trim_blocks=True)
        template = environment.get_template('analysis_report.txt.jinja2')
        return template.render(report=self)

    def to_json(self, pretty: bool = False) -> Text:
        return json.dumps(self.to_dict(), indent=2 if pretty else None)

    def __repr__(self):
        return (
            '<Report '
            'start_time={0.start_time} '
            'end_time={0.end_time} '
            'reports={0.reports}'
            '>'
        ).format(self)
