import html

data = source()
data = html.unescape(data)
sink(data)
