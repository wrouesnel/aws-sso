import dataclasses
from enum import Enum

import click
import ruamel.yaml
import ruamel.yaml as yaml
import json
import tabulate as _tabulate

class OutputFmt(Enum):
    Table = "table"
    Json = "json"
    Yaml = "yaml"

_tablefmt = "simple"
_headers = False
_outputfmt = OutputFmt.Table

def set_output_format(value: OutputFmt):
    global _outputfmt
    _outputfmt = value

def set_table_format(value: str):
    global _tablefmt
    _tablefmt = value

def set_headers(value: bool):
    global _headers
    _headers = value

def tabulate(tabular_data, headers) -> str:
    """Wrapper method to apply global output format settings"""
    if _outputfmt != OutputFmt.Table:
        # Convert the table into a structured data-ish thing
        output = []
        for row in tabular_data:
            output.append(dict(zip(headers, row)))

        if _outputfmt == OutputFmt.Yaml:
            return ruamel.yaml.round_trip_dump(output, default_flow_style=False)
        elif _outputfmt == OutputFmt.Json:
            return json.dumps(output, indent=True)
        else:
            raise NotImplementedError("output format not implemented")

    if not _headers:
        headers = ()
    return _tabulate.tabulate(tabular_data=tabular_data, headers=headers, tablefmt=_tablefmt)

