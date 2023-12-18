import re
import hashlib

def validate_password(password):
    # Vérification de la longueur du mot de passe
    if len(password) < 8:
        return False

    # Vérification des caractères spéciaux
    if not re.search("[!@#$%^&*]", password):
        return False

    # Vérification des lettres majuscules, minuscules et chiffres
    if not re.search("[A-Z]", password) or not re.search("[a-z]", password) or not re.search("[0-9]", password):
        return False

    return True

def encrypt_password(password):
    # Utilisation de l'algorithme de hachage SHA-256 pour crypter le mot de passe
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

def main():
    while True:
        password = input("Choisissez un mot de passe : ")

        if validate_password(password):
            hashed_password = encrypt_password(password)
            print("Mot de passe valide.")
            print("Mot de passe crypté :", hashed_password)
            break
        else:
            print("Le mot de passe ne respecte pas les exigences de sécurité. Veuillez choisir un nouveau mot de passe.")

if __name__ == '__main__':
    main()