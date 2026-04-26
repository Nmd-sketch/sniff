import sniff
import os
print("I am importing from:", sniff.__file__)


# Tell Python to look for files in the directory where THIS script is located
search_dir = os.path.dirname(os.path.abspath(__file__))

print("--- Finding all C++ files ---")
cpp_files = sniff.glob_find(search_dir, "cpp")

for entry in cpp_files:
    # Look at this! We get real Python objects with properties!
    print(f"File: {entry.path} | Size: {entry.size_bytes} bytes")

print(f"\nFound {len(cpp_files)} C++ files.")

print("\n--- Finding large files (> 1000 bytes) ---")
# Notice we use Python keyword arguments! Pybind11 mapped them perfectly.
large_files = sniff.find(search_dir, min_size=1000)

for entry in large_files:
    print(f"Big file: {entry.path}")



