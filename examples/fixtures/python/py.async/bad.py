async def fetch():
    x = source()
    return x

async def main():
    data = await fetch()
    sink(data)
