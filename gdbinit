# break in main()
break *0x804841d

# break right before read()
# break *0x8048416

# break right after read()
# break *0x804842b
# break *0x804841b

# break on write's plt entry
break *0x804830c

# break on read's plt entry
break *0x804832c

# run the binary
run < output

# print the source code for main() and the read_whatever() function.
x/25i 0x80483f4
