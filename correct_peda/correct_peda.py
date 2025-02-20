import re

files_to_update = [
    '/opt/peda/peda.py',
    '/opt/peda/lib/utils.py',
    '/opt/peda/lib/nasm.py'
]

# Function to relace char string in files
def update_file(file_path):
    with open(file_path, 'r') as file:
        file_content = file.read()

    # Replace old version of strings to new ones
    updated_content = re.sub(r're\.findall\("', 're.findall(r"', file_content)
    updated_content = re.sub(r're\.search\("', 're.search(r"', updated_content)
    updated_content = re.sub(r're\.match\("', 're.match(r"', updated_content)
    updated_content = re.sub(r're\.compile\("', 're.compile(r"', updated_content)
    updated_content = re.sub(r're\.escape\("', 're.escape(r"', updated_content)

    # Replace escape strings
    updated_content = re.sub(r'\\\s', r'\\ ', updated_content)  # Remplace \ par \ espace
    updated_content = re.sub(r'\\\?', r'\\?', updated_content)  # Remplace \? par \\?
    updated_content = re.sub(r'\\\(', r'\\(', updated_content)  # Remplace \( par \\(

    # Replace backslashes followed by CRLF ans \t
    updated_content = re.sub(r'\\(\r?\n)+[\s\t]+', '', updated_content)

    # Few specifics lines
    updated_content = re.sub(r're\.escape\(asmcode\)\.replace\("\\\\ ", ".*"\)\.replace\("\\\\\?", ".*"\)',
                             r're.escape(asmcode).replace(r"\\ ", ".*").replace(r"\\?", ".*")', updated_content)
    updated_content = re.sub(r'pattern = re\.compile\(b\'\|'\.join\(JMPCALL\)\.replace\(b\' \', b\'\\\\ \'\)\)',
                             r'pattern = re.compile(b\'|\'.join(JMPCALL).replace(b\' \', b\'\\ \'\))', updated_content)

    if file_content != updated_content:
        with open(file_path, 'w') as file:
            file.write(updated_content)
        print(f"Les modifications ont été appliquées avec succès dans {file_path}.")
    else:
        print(f"Aucune modification n'a été nécessaire dans {file_path}.")

# Apply to every important files
for file_path in files_to_update:
    update_file(file_path)