import os
import json
import hashlib

HASH_TABLE_FILE = "hash_table.json"


def hash_file(file_path, algo="sha256"):
    h = hashlib.new(algo)
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def traverse_directory(directory_path):
    file_paths = []
    for root, _, files in os.walk(directory_path):
        for name in files:
            file_paths.append(os.path.join(root, name))
    return file_paths


def generate_table(directory_path):
    directory_path = os.path.abspath(directory_path)
    files = traverse_directory(directory_path)

    table = []
    for file_path in files:
        try:
            file_hash = hash_file(file_path)
            table.append({"filepath": file_path, "hash": file_hash})
        except (PermissionError, FileNotFoundError):
            continue

    data = {
        "base_directory": directory_path,
        "algorithm": "sha256",
        "files": table
    }

    with open(HASH_TABLE_FILE, "w", encoding="utf-8") as out:
        json.dump(data, out, indent=2)

    print("Hash table generated.")


def validate_hash():
    if not os.path.exists(HASH_TABLE_FILE):
        print("No hash table found. Generate one first.")
        return

    with open(HASH_TABLE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    base_dir = data["base_directory"]
    algo = data.get("algorithm", "sha256")
    stored_files = {item["filepath"]: item["hash"] for item in data["files"]}

    current_file_list = traverse_directory(base_dir)
    current_files = set(current_file_list)
    stored_file_set = set(stored_files.keys())

    added = current_files - stored_file_set
    deleted = stored_file_set - current_files

    for file_path in sorted(added):
        print(f"{file_path} was added.")

    for file_path in sorted(deleted):
        print(f"{file_path} was deleted.")

    common = current_files & stored_file_set
    for file_path in sorted(common):
        try:
            new_hash = hash_file(file_path, algo=algo)
            if new_hash == stored_files[file_path]:
                print(f"{file_path} hash is valid.")
            else:
                print(f"{file_path} hash is invalid.")
        except (PermissionError, FileNotFoundError):
            print(f"{file_path} could not be checked.")


def main():
    print("1) Generate new hash table")
    print("2) Verify hashes")
    choice = input("Choose 1 or 2: ").strip()

    if choice == "1":
        directory = input("Enter directory path: ").strip()
        if not os.path.isdir(directory):
            print("That directory does not exist.")
            return
        generate_table(directory)

    elif choice == "2":
        validate_hash()

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
