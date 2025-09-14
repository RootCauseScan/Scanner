def get_data():
    return source()

def log_value(v):
    sink(v)

def main():
    d = get_data()
    log_value(d)
