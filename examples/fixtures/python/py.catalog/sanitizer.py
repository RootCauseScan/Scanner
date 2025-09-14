def main():
    data = custom_source()
    data = custom_clean(data)
    custom_sink(data)
