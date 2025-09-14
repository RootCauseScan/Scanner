def compute(flag, items):
    if flag:
        result = 0
    for item in items:
        result += item
    while result < 10:
        result += 1
    return result
