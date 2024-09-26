try:
    import importlib.metadata
except ImportError:
    # compatibility with python < 3.8
    class Placeholder(object):
        version = ''
    dist = Placeholder()
else:
    dist = importlib.metadata.distribution(__name__)
