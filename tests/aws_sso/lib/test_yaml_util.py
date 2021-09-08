import dataclasses
import io

import ruamel.yaml

import aws_sso.lib.yaml_util as yaml_util


def test_dataclass_representer():
    """Test the dataclass ruamel yaml representer"""

    yaml = ruamel.yaml.YAML(typ="safe")
    yaml.Representer = yaml_util.SafeDataclassRepresenter
    yaml.default_flow_style = False

    @dataclasses.dataclass
    class T():
        x: str

    t = T(x="hello")
    output = io.StringIO()
    yaml.dump(t, output)
    assert output.getvalue().strip() == "x: hello".strip()
