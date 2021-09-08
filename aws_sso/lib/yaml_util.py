import dataclasses
from typing import Any

import ruamel.yaml
from ruamel.yaml.representer import RepresenterError


class SafeDataclassRepresenter(ruamel.yaml.SafeRepresenter):
    def represent_object(self, data: Any):
        if dataclasses.is_dataclass(data):
            return self.represent_dict(dataclasses.asdict(data))
        raise RepresenterError(f"cannot represent object: {data}")

SafeDataclassRepresenter.add_multi_representer(object, SafeDataclassRepresenter.represent_object)
