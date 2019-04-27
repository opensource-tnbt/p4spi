"""Generic class to hold sotware version information shown in the report
"""

class Version(object):
    """Container to keep software version details
    """
    def __init__(self, name, version, git_tag='NA'):
        """Create Version object with given data
        """
        self._version = {'name' : name, 'version' : version, 'git_tag' : git_tag}

    def set_value(self, key, value):
        """Upate given `key` by given `value`
        """
        self._version[key] = value

    def get(self):
        """Get content of version object
        """
        return self._version
