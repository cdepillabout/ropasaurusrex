# break in main()
break *0x804841d

# break after read()
break *0x804842b

# run the binary
run < output

# print the source code for main() and the read_whatever() function.
x/25i 0x80483f4
