def demo():
    obj = source()
    arr = source()
    idx = 0
    x = obj.attr
    y = arr[idx]
    val = source()
    obj.attr = val
    arr[idx] = val
    return x, y, obj, arr
