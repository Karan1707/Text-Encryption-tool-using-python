import tkinter as tk
from tkinter import messagebox

def caesar_cipher_encrypt(plaintext, key):
    ciphertext = ""
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            if char.islower():
                shifted = (ord(char) - ord('a') + ord(key[key_index].lower()) - ord('a')) % 26 + ord('a')
            elif char.isupper():
                shifted = (ord(char) - ord('A') + ord(key[key_index].lower()) - ord('a')) % 26 + ord('A')
            ciphertext += chr(shifted)
            key_index = (key_index + 1) % len(key)
        else:
            ciphertext += char
    return ciphertext

def caesar_cipher_decrypt(ciphertext, key):
    plaintext = ""
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            if char.islower():
                shifted = (ord(char) - ord('a') - (ord(key[key_index].lower()) - ord('a'))) % 26 + ord('a')
            elif char.isupper():
                shifted = (ord(char) - ord('A') - (ord(key[key_index].lower()) - ord('a'))) % 26 + ord('A')
            plaintext += chr(shifted)
            key_index = (key_index + 1) % len(key)
        else:
            plaintext += char
    return plaintext

def perform_action():
    choice = choice_var.get()
    message = message_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()

    if not key.isalpha():
        messagebox.showerror("Invalid Key", "The key must contain only alphabetic characters.")
        return

    if choice == "Encrypt":
        result = caesar_cipher_encrypt(message, key)
    else:
        result = caesar_cipher_decrypt(message, key)
    
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, result)

def create_gui():
    global choice_var, message_entry, key_entry, result_text

    root = tk.Tk()
    root.title("Caesar Cipher Encryptor/Decryptor")
    root.geometry("500x500")
    root.configure(bg="#f0f0f0")

    title_label = tk.Label(root, text="Caesar Cipher Encryptor/Decryptor", font=("Helvetica", 16, "bold"), bg="#f0f0f0")
    title_label.pack(pady=10)

    frame = tk.Frame(root, bg="#f0f0f0")
    frame.pack(pady=10)

    tk.Label(frame, text="Choose an option:", bg="#f0f0f0", font=("Helvetica", 12)).grid(row=0, column=0, sticky=tk.W, pady=5)
    
    choice_var = tk.StringVar(value="Encrypt")
    encrypt_radio = tk.Radiobutton(frame, text="Encrypt", variable=choice_var, value="Encrypt", bg="#f0f0f0", font=("Helvetica", 12))
    decrypt_radio = tk.Radiobutton(frame, text="Decrypt", variable=choice_var, value="Decrypt", bg="#f0f0f0", font=("Helvetica", 12))
    encrypt_radio.grid(row=1, column=0, sticky=tk.W)
    decrypt_radio.grid(row=1, column=1, sticky=tk.W)

    tk.Label(frame, text="Enter the message:", bg="#f0f0f0", font=("Helvetica", 12)).grid(row=2, column=0, sticky=tk.W, pady=5)
    message_entry = tk.Text(frame, height=5, width=50, font=("Helvetica", 12))
    message_entry.grid(row=3, column=0, columnspan=2, pady=5)

    tk.Label(frame, text="Enter the key (a word or phrase):", bg="#f0f0f0", font=("Helvetica", 12)).grid(row=4, column=0, sticky=tk.W, pady=5)
    key_entry = tk.Entry(frame, width=50, font=("Helvetica", 12))
    key_entry.grid(row=5, column=0, columnspan=2, pady=5)

    submit_button = tk.Button(root, text="Submit", command=perform_action, font=("Helvetica", 12), bg="#007bff", fg="#ffffff")
    submit_button.pack(pady=10)

    result_frame = tk.Frame(root, bg="#f0f0f0")
    result_frame.pack(pady=10)
    tk.Label(result_frame, text="Result:", bg="#f0f0f0", font=("Helvetica", 12)).pack(anchor=tk.W)
    result_text = tk.Text(result_frame, height=5, width=50, font=("Helvetica", 12), bg="#e0e0e0", wrap=tk.WORD)
    result_text.pack(fill=tk.BOTH, expand=True, pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
