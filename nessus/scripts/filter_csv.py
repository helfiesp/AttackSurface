def iterate_csv_file(filename):
    try:
        with open(filename, "r") as file:
            for line in file:
                print(line.strip())  # Strip whitespace and print each line
    except FileNotFoundError:
        print("File not found.")

if __name__ == "__main__":
    exported_file = "exported_scan_20.csv"  # Update with the actual filename
    iterate_csv_file(exported_file)