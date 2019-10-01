import pydasm
import pefile

exe_path = "_conda.exe"

# Store the file in a variable
fd = open(exe_path, 'rb')
data = fd.read()
fd.close()

# Get the EP, raw size and virtual address of the code
pe = pefile.PE(exe_path)
ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
raw_size = pe.sections[0].SizeOfRawData
ep_va = ep + pe.OPTIONAL_HEADER.ImageBase

print ("[*] Entry Point: " + hex(ep))
print ("[*] Raw Size: " + hex(raw_size))
print ("[*] EP VA: " + hex(ep_va))

# Start disassembly at the EP
offset = ep

# Loop until the end of the .text section
while offset < (offset + raw_size):
    # Get the first instruction
    i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
    # Print a string representation if the instruction
    print (pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_va + offset))
    # Go to the next instruction
    offset += i.length