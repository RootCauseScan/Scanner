import helpers.security as hs
from helpers.security import sanitize as clean

data = source()
alias = data
sink(alias)
