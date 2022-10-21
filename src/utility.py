import copy


def get_json_property(json_object, property_name, default_value=None):
    if json_object is None:
        return None
    clone_object = copy.deepcopy(json_object)
    names = str(property_name).split(".")
    for name in names:
        if name in clone_object:
            clone_object = clone_object[name]
        else:
            return None
    return clone_object


class CyberException(Exception):
    def __init__(self, msg):
        self.msg = msg


class Messages:
    ERROR_NOT_IMPLEMENTED = "Not implemented"
