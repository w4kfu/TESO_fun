import re

def tokenize(text, match=re.compile("([idel])|(\d+):|(-?\d+)").match):
    i = 0
    while i < len(text):
        m = match(text, i)
        s = m.group(m.lastindex)
        i = m.end()
        if m.lastindex == 2:
            yield "s"
            yield text[i:i+int(s)]
            i = i + int(s)
        else:
            yield s

def bedecode_item(next, token):
    if token == "i":
        data = int(next())
        if next() != "e":
            raise ValueError
    elif token == "s":
        data = next()
    elif token == "l" or token == "d":
        data = []
        tok = next()
        while tok != "e":
            data.append(decode_item(next, tok))
            tok = next()
        if token == "d":
            data = dict(zip(data[0::2], data[1::2]))
    else:
        raise ValueError
    return data

def bedecode(text):
    try:
        src = tokenize(text)
        data = bedecode_item(src.next, src.next())
        for token in src:
            raise SyntaxError("trailing junk")
    except (AttributeError, ValueError, StopIteration):
        raise SyntaxError("syntax error")
    return data

if __name__ == '__main__':
    data = open("out3/metafile.solid", "rb").read()
    torrent = bedecode(data)
    for file in torrent["info"]["files"]:
        print "%r - %d bytes" % ("/".join(file["path"]), file["length"])
    print torrent["reliable"]
