import yaml

def read_cfg(path):
    with open(path) as f:
        return yaml.load(f)
