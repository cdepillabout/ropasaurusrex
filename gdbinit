# break in main()
break *0x804841d

# run the binary
run

# print the source code for main() and the read_whatever() function.
x/25i 0x80483f4
