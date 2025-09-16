# Bad: dynamic eval or exec
import sys
s = sys.argv[1]
eval(s)

