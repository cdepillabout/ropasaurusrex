# break in main()
break *0x804841d

# break right before read()
break *0x8048416

# break right after read()
# break *0x804842b
break *0x804841b

# run the binary
run < output

# print the source code for main() and the read_whatever() function.
x/25i 0x80483f4
