import tempfile

with tempfile.NamedTemporaryFile() as tmp:
    tmp.write(b"data")
