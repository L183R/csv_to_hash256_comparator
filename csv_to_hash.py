import hashlib
import csv
import tkinter as tk
from tkinter import filedialog, messagebox

def sha256_hash_string(input_string):
    sha256 = hashlib.sha256()
    sha256.update(input_string.encode())
    return sha256.hexdigest()

def find_matching_password(csv_file, target_hash):
    with open(csv_file, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            password = row[0].strip()  # Asegurarse de eliminar espacios en blanco al inicio y al final
            hash_hex = sha256_hash_string(password)
            if hash_hex == target_hash:
                return password
    return None

def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if file_path:
        entry_csv.delete(0, tk.END)
        entry_csv.insert(0, file_path)

def check_hash():
    csv_file = entry_csv.get()
    target_hash = entry_hash.get().strip()
    
    if not csv_file or not target_hash:
        messagebox.showerror("Error", "Por favor, carga un archivo CSV e ingresa un hash.")
        return
    
    matching_password = find_matching_password(csv_file, target_hash)
    if matching_password:
        messagebox.showinfo("Resultado", f"La contraseña correspondiente al hash {target_hash} es: {matching_password}")
    else:
        messagebox.showinfo("Resultado", f"No se encontró ninguna contraseña que corresponda al hash {target_hash}")

def hash_string():
    input_string = entry_string.get().strip()
    if not input_string:
        messagebox.showerror("Error", "Por favor, ingresa una cadena de texto para hashear.")
        return
    
    hash_result = sha256_hash_string(input_string)
    entry_hash_result.delete(0, tk.END)
    entry_hash_result.insert(0, hash_result)

# Configuración de la interfaz gráfica
root = tk.Tk()
root.title("Comparador de Hashes SHA-256")

# Etiquetas y entradas para el archivo CSV
label_csv = tk.Label(root, text="Archivo CSV:")
label_csv.grid(row=0, column=0, padx=10, pady=10)

entry_csv = tk.Entry(root, width=50)
entry_csv.grid(row=0, column=1, padx=10, pady=10)

button_browse = tk.Button(root, text="Cargar", command=open_file)
button_browse.grid(row=0, column=2, padx=10, pady=10)

# Etiquetas y entradas para el hash a comparar
label_hash = tk.Label(root, text="Hash a comparar:")
label_hash.grid(row=1, column=0, padx=10, pady=10)

entry_hash = tk.Entry(root, width=50)
entry_hash.grid(row=1, column=1, padx=10, pady=10)

# Botón para comparar el hash
button_check = tk.Button(root, text="Comparar Hash", command=check_hash)
button_check.grid(row=2, column=0, columnspan=3, padx=10, pady=10)

# Etiquetas y entradas para hashear una cadena
label_string = tk.Label(root, text="Cadena de texto para hashear:")
label_string.grid(row=3, column=0, padx=10, pady=10)

entry_string = tk.Entry(root, width=50)
entry_string.grid(row=3, column=1, padx=10, pady=10)

button_hash_string = tk.Button(root, text="Hashear Cadena", command=hash_string)
button_hash_string.grid(row=3, column=2, padx=10, pady=10)

# Campo para mostrar el resultado del hash
label_hash_result = tk.Label(root, text="Hash resultante:")
label_hash_result.grid(row=4, column=0, padx=10, pady=10)

entry_hash_result = tk.Entry(root, width=50)
entry_hash_result.grid(row=4, column=1, padx=10, pady=10)

root.mainloop()
