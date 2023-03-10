
def vigenere_cipher(plaintext, key):
    """Encripta texto com a cifra de vigenere"""
    ciphertext = ""
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            # Converte para maiúsculo para consistência
            char = char.upper()
            key_char = key[key_index % len(key)].upper()
            # Encripta
            encrypted_char = chr(
                ((ord(char) + ord(key_char) - 2 * ord('A')) % 26) + ord('A'))
            ciphertext += encrypted_char
            key_index += 1
        else:
            # Caracteres não alfabéticos são adicionados direto ao texto cifrado.
            ciphertext += char
    return ciphertext


def vigenere_decipher(ciphertext, key):
    """Decripta uma cifra vigenere baseado em uma chave"""
    plaintext = ""
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            # Converte para maiusculo para consistencia
            char = char.upper()
            key_char = key[key_index % len(key)].upper()
            # Perform decryption
            decrypted_char = chr(
                ((ord(char) - ord(key_char) + 26) % 26) + ord('A'))
            plaintext += decrypted_char
            key_index += 1
        else:
            # Caracteres não alfabéticos são adicionados direto ao texto cifrado.
            plaintext += char
    return plaintext


def cypher():
    plaintext = "The quick brown fox jumps over the lazy dog."
    key = "secret"
    ciphertext = vigenere_cipher(plaintext, key)
    print(f"Texto Plano: {plaintext}")
    print(f"Criptografia: {ciphertext}")
    return ciphertext


def decypher(cyphertext):
    key = "secret"
    plaintext = vigenere_decipher(cyphertext, key)
    print(f"Descriptografia: {plaintext.lower()}")


decypher(cypher())
