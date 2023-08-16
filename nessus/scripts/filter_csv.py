import csv
import json
import pandas as pd

def IterateCSV(filename):
    # Iterating through the CSV file to get the dataset.
    with open(filename, "r") as file:
        for x in file:
            data = x
            break

    # Replacing booleans with python compatible ones as the ones from nessus are not compatible.
    data = dict(eval(data.replace("false", "False").replace("true", "True").replace("null", "None")))



    for item in data["info"]:
        print(item)

    print(data.keys())

if __name__ == "__main__":
    exported_file = "C:/Users/Helfie/Downloads/scan.csv"  # Update with the actual filename
    IterateCSV(exported_file)
