import csv
import json

def convert_csv_to_json(filename):
    try:
        json_objects = []
        with open(filename, "r") as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                json_objects.append(row)
        return json_objects
    except FileNotFoundError:
        print("File not found.")

if __name__ == "__main__":
    exported_file = "data/exported_scan_20.csv"  # Update with the actual filename
    json_objects = convert_csv_to_json(exported_file)

    for obj in json_objects:
        print(json.dumps(obj, indent=4))  # Print each JSON object with indentation





