import lief

def replace_debug_line_section(hello_path, balls_path):
    # Step 1: Read the bytes from the 'balls' file
    with open(balls_path, 'rb') as balls_file:
        balls_data = balls_file.read()

    # Step 2: Load the ELF file (hello) using LIEF
    binary = lief.parse(hello_path)

    # Step 3: Find the .debug_line section in the ELF file
    debug_line_section = None
    for section in binary.sections:
        if section.name == ".debug_line":
            debug_line_section = section
            break

    if debug_line_section is None:
        print("No .debug_line section found in the file!")
        return

    # Step 4: Replace the content of the .debug_line section with the bytes from the 'balls' file
    debug_line_section.content = list(balls_data)

    # Step 5: Save the modified ELF file back to disk
    output_path = hello_path
    binary.write(output_path)
    print(f"Modified ELF file written to: {output_path}")

# Call the function to replace the .debug_line section
replace_debug_line_section("./hello", "./balls")

