'''
    challenge was mostly just digging through a bunch of C++ disassembler code just to find a read function that has a parameter of the sum of your first input minus a value. so if you make your input that value then the program will read from stdin and boom you're done

    didnt feel like making a script to find me the right character combination so i made this and then tested things out until I got it. 

    sent "zzzzzzzzzzzzAJz" into the input then got the read() to read from stdin and then sent in 
    "make every program a filter" to pass verification and get the flag

    ezpz lemon squeezy... now i can go back to working on VIP Blacklist :((((((
'''


while True:
    usr_input = input("enter string: ")

    char_sum = 0
    for char in usr_input:
        char_sum += ord(char)

    print(hex(char_sum))
