import helpers.security as hs
from helpers.security import sanitize as clean

data = source()
data = clean(data)
alias = data
sink(alias)
