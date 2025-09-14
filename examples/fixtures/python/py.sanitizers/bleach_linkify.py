import bleach

data = source()
data = bleach.linkify(data)
sink(data)
