import hashlib
import random

# Numero primo de RFC3526 de 1536 bits - MODP Group
p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",16)
g = 2

print("--- Parametros Publicos ---")
print("Numero primo p:", p)
print("Base g:", g)

# Creacion de claves secretas (256 bits cada una)
# Generamos las claves de Alice y Bob de forma aleatoria
sAlice = random.getrandbits(256)  # Clave privada de Alice
sBob   = random.getrandbits(256)  # Clave privada de Bob

# Eve crea dos claves para interceptar ambas comunicaciones
sEve_Alice = random.getrandbits(256)  # Clave para simular a Bob ante Alice
sEve_Bob   = random.getrandbits(256)  # Clave para simular a Alice ante Bob

print("\n--- Claves Privadas Generadas ---")
print("Clave privada de Alice:", sAlice)
print("Clave privada de Bob:", sBob)
print("Clave privada de Eve (para Alice):", sEve_Alice)
print("Clave privada de Eve (para Bob):", sEve_Bob)

# 1. Alice calcula y envia su valor publico: A = g^sAlice mod p
A = pow(g, sAlice, p)
print("\nAlice envia (A):", A)

# Eve intercepta A y, en vez de dejarlo pasar, manda su propio valor a Bob:
# Valor de Eve para la sesion con Bob: E_A = g^sEve_Alice mod p
E_A = pow(g, sEve_Alice, p)
print("Eve intercepta A y envia a Bob (E_A):", E_A)

# 2. Bob calcula y envia su valor publico: B = g^sBob mod p
B = pow(g, sBob, p)
print("\nBob envia (B):", B)

# Eve intercepta B y lo sustituye por su valor antes de enviarlo a Alice:
# Valor de Eve para la sesion con Alice: E_B = g^sEve_Bob mod p
E_B = pow(g, sEve_Bob, p)
print("Eve intercepta B y envia a Alice (E_B):", E_B)

# Calculo de las claves compartidas

# Entre Alice y Eve:
# Alice utiliza el valor de Eve (E_B) pensando que es de Bob
clave_Alice_Eve = pow(E_B, sAlice, p)
# Eve usa su clave (sEve_Bob) y el valor de A interceptado para calcular la misma clave
clave_Eve_Alice = pow(A, sEve_Bob, p)

print("\n--- Clave Compartida entre Alice y Eve ---")
print("Alice calcula:", clave_Alice_Eve)
print("Eve calcula:  ", clave_Eve_Alice)

if clave_Alice_Eve == clave_Eve_Alice:
    print("= La clave entre Alice y Eve coincide.")
else:
    print("= Error: la clave entre Alice y Eve no coincide.")

# Entre Bob y Eve:
# Bob usa el valor modificado por Eve (E_A) creyendo que es de Alice
clave_Bob_Eve = pow(E_A, sBob, p)
# Eve calcula la clave usando su clave (sEve_Alice) y el valor B interceptado
clave_Eve_Bob = pow(B, sEve_Alice, p)

print("\n--- Clave Compartida entre Bob y Eve ---")
print("Bob calcula:", clave_Bob_Eve)
print("Eve calcula:", clave_Eve_Bob)

if clave_Bob_Eve == clave_Eve_Bob:
    print("= La clave entre Bob y Eve coincide.")
else:
    print("= Error: la clave entre Bob y Eve no coincide.")

# Aplicacion de SHA-512 para obtener un resumen de cada clave compartida
# Se calcula el numero de bytes necesarios para representar la clave
byte_len_AE = (clave_Alice_Eve.bit_length() + 7) // 8
byte_len_BE = (clave_Bob_Eve.bit_length() + 7) // 8

hash_AE = hashlib.sha512(clave_Alice_Eve.to_bytes(byte_len_AE, byteorder='big')).hexdigest()
hash_BE = hashlib.sha512(clave_Bob_Eve.to_bytes(byte_len_BE, byteorder='big')).hexdigest()

print("\n--- Hash de las Claves Compartidas ---")
print("Hash entre Alice y Eve:", hash_AE)
print("Hash entre Bob y Eve:  ", hash_BE)
