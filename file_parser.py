import re

# Open the input and output files
with open('Worker.txt', 'r') as input_file, open('parsed_worker.log', 'w') as output_file:
    # Iterate through each line in the input file
    for line in input_file:
        # Use regular expression to match lines starting with '2024-05-02' or '2024-05-03'
        if re.match(r'^(2024-05-02|2024-05-03)', line):
            # Write matching lines to the output file
            output_file.write(line)
