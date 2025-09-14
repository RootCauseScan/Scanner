from helpers.security import sanitize

data = source()
alias = data
copy = alias
copy = sanitize(copy)
sink(copy)
