try:
    # compatibility with dnspython >= 2.7.0
    from dns.edns import GenericOption, OptionType, register_type
    for o in list(OptionType):
      register_type(GenericOption, o)
except ImportError:
    pass

try:
    import importlib.metadata
except ImportError:
    # compatibility with python < 3.8
    class Placeholder(object):
        version = ''
    dist = Placeholder()
else:
    dist = importlib.metadata.distribution(__name__)
