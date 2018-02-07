import csv

def read_keepass(filename, pw):
    f = open(filename, newline='', encoding='utf-8')
    reader = csv.DictReader(f)
    for row in reader:
        data = {
            'password': row['Password'],
            'username': row['Login Name'],
            'notes': row['Comments'],
            'url': row['Web Site']
        }
        data = {k:v for k, v in data.items() if v}
        pw.add(row['Account'], **data)

