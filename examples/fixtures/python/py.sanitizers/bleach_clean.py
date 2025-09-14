import bleach

data = source()
data = bleach.clean(data)
sink(data)
