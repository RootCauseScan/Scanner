def compute(flag, items):
    result = 0
    for item in items:
        result += item
    if flag:
        result += 1
    while result < 10:
        result += 1
    return result
