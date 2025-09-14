import html

data = source()
data = html.escape(data)
sink(data)
