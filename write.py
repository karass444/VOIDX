html = open('/home/kara/VOIDX/index.html').read()
print(len(html), "bytes")
print("screens:", html.count('class="screen"'))
