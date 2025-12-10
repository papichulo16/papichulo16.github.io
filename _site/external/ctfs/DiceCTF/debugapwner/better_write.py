import lief
import struct

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

    # Step 4: Rebuild the .debug_line header
    # The header includes the section length and other fields.
    # Let's assume the original prologue and other fixed fields remain the same.

    # The initial header structure
    # [Length] (4 bytes), [DWARF Version] (2 bytes), [Prologue Length] (2 bytes),
    # [Min Instruction Length] (1 byte), [Default Is Statement] (1 byte),
    # [Line Base] (1 byte), [Line Range] (1 byte), [Opcode Base] (1 byte),
    # [Standard Opcodes] (variable size based on `Opcode Base`)

    prologue_length = 12  # This is usually 12 bytes for the header in DWARF 3+
    min_instruction_length = 1  # Typically 1 byte
    default_is_statement = 1  # Default is a statement (true)
    line_base = 0  # Base value for line numbers
    line_range = 1  # Range for each line number
    opcode_base = 10  # Standard opcodes (the number is dependent on the DWARF version)
    
    # The length of the content (not counting the header)
    content_length = len(balls_data)

    # Calculate the full length of the section (header + content)
    full_length = prologue_length + content_length - 4

    # Update the section length
    debug_line_section.size = full_length

    # Step 5: Construct the new header for the .debug_line section
    # DWARF version (3 for DWARF 3 or higher)
    dwarf_version = 3
    header = struct.pack(
        "<IHIBBbBB",  # Format: Little Endian, unsigned int (length), unsigned short (version), etc.
        full_length,  # Total length of the section
        dwarf_version,  # DWARF version
        prologue_length,  # Prologue length
        min_instruction_length,  # Minimum instruction length
        default_is_statement,  # Default is a statement
        line_base,  # Line base
        line_range,  # Line range
        opcode_base  # Opcode base
    )

    # Step 6: Replace the section content with the new header and the balls data
    debug_line_section.content = list(header) + list(balls_data)

    # Step 7: Write the modified ELF file back to disk
    output_path = hello_path
    binary.write(output_path)
    print(f"Modified ELF file written to: {output_path}")

# Specify the paths to the hello and balls files
hello_file_path = "hello"
balls_file_path = "balls"

# Call the function to replace the .debug_line section
replace_debug_line_section(hello_file_path, balls_file_path)

