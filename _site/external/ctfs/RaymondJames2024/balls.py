arr = []

for f in open("alice.txt", "r"):
    if len(f) > 1:
        
        print(chr(len(f) - 1), end="")

