import sys
'''
Regresa los primeros 8 bytes de una archivo dada su ruta.
'''
def get_magic_bytes(filepath, num_bytes=8):
    try:
        with open(filepath, 'rb') as f:
            magic_bytes = f.read(num_bytes)
        return magic_bytes
    except FileNotFoundError:
        return None

'''
Imprime en terminal las representaciones en hexadecimal y enteros de un arreglo de bytes
'''
def inspect(b):
    print("bytes: ", b)
    print("int: ",list(b))
    print("hex: ", b.hex())
    print("\n")

# Esto Hardcodeado fue para analizar
# file_path_1 = 'files/file1.lol'
# file_path_2 = 'files/file2.lol'
# file_path_3 = 'files/file3.lol'
# file_path_4 = 'files/file4.lol'

# inspect(get_magic_bytes(file_path_1)) # FILE1 -> MP4
# inspect(get_magic_bytes(file_path_2))
# inspect(get_magic_bytes(file_path_3))
# inspect(get_magic_bytes(file_path_4)) # FILE4 -> JPG

'''
Retornar el inverso de a módulo 256, cuando existe.
Notemos que en Z^256 sólo los números impares tienen inverso.
Este es el algoritmod de Euclides extentido. Es O(log n) ^^
'''
def getInv(a):
    if a % 2 == 0:
        raise ValueError("No existe el inverso modular para números pares en Z^256")
    
    t = 0
    newt = 1
    r = 256
    newr = a

    while newr != 0:
        q = r // newr
        temp = newt
        newt = t - q*newt
        t = temp

        temp = newr
        newr = r - q*newr
        r = temp

    if t < 0:
        t += 256
    
    return t

'''
Diccionario global con todos los inversos módulo 256
'''
inversos256 = {}
for i in range(1,256,2):
    inversos256[i] = getInv(i)


'''
Cifrado de César (también decifrador con -k) ^^
'''
def cesar(data, k, cifrar):
    if not cifrar:
        k = k * -1
    return bytes((b + k) % 256 for b in data)


'''
Cifrado por decimado (multiplicativo) sobre Zmod256.
Para que sea válido, k debe ser coprimo con 256 (es decir, k debe ser impar).
Cifrado: C = (k * P) mod 256
Descifrado: P = (k^-1 * C) mod 256
'''
def decimado(data, k, cifrar): 
    if cifrar: 
        return bytes((k * b) % 256 for b in data)
    else: 
        inv = inversos256.get(k)
        if inv is None: 
            raise ValueError("k no tiene inverso en Z256")
        return bytes((inv * b) % 256 for b in data)

'''
Implementación del cifrado afín sobre bytes.
Cifrado Uso:
# python3 practica2.py archivo -a afin -c -k1 a -k2 b -o salida
Descifrado Uso: 
# python3 practica2.py archivo.lol -a afin -d -k1 a -k2 b -o salida.ext
'''
def afin(data, a, b, cifrar):

    if cifrar:
        return bytes((a*bte + b) % 256 for bte in data)

    else:
        inv = inversos256.get(a)

        if inv is None:
            raise ValueError("a no tiene inverso en Z256")

        return bytes((inv*(bte - b)) % 256 for bte in data)

'''
Ataque de fuerza bruta para el cifrado de decimado.
Itera sobre todos los posibles inversos multiplicativos en Z256 (llaves impares).
Utiliza firmas de archivos (Magic Bytes) para identificar si el descifrado fue exitoso.
'''
def fuerza_bruta_decimado(data):

    firmas = [
        "25504446",  # PDF
        "504b0304",  # DOCX/EPUB
        "494433",    # MP3
        "52494646",  # WAV
        "4f676753"   # OGG
    ]

    for k in range(1,256,2):

        intento = decimado(data, k, False)

        magic = intento[:4].hex()

        if any(magic.startswith(f) for f in firmas):

            print("Este es el bueno")
            print("k =",k)
            print("magic_bytes =",magic)

            return intento   

    return None
'''
Ataque de fuerza bruta contra cifrado afín.
Prueba todas las combinaciones posibles de (a, b) en Z256.
Solo se prueban valores impares de 'a'
Se descifran los primeros 32 bytes del archivo y se comparan con firmas
conocidas de magic bytes. Solo si se detecta firma válida se descifra todo el archivo. 

Uso:
# python3 practica2.py archivo.lol -a fuerza_bruta_afin -o salida.ext
'''
def fuerza_bruta_afin(data):

    firmas = [
        "25504446",  # PDF
        "504b0304",  # DOCX/EPUB
        "494433",    # MP3
        "52494646",  # WAV
        "4f676753",  # OGG
        "89504e47",  # PNG
        "ffd8ff"     # JPG
    ]

    for a in range(1,256):

        if a % 2 == 0:
            continue

        inv = inversos256[a]

        for b in range(256):

            test = bytes((inv*(y-b)) % 256 for y in data[:32])

            magic = test[:4].hex()

            if any(magic.startswith(f) for f in firmas):

                print("Clave encontrada")
                print("a =",a,"b =",b)

                return bytes((inv*(y-b)) % 256 for y in data)

    return None

def base64(data, cifrar):
    if cifrar:
        return base64_encode(data)
    else:
        return base64_decode(data)

'''
Implementación del codificado Base64
Cifrado Uso:
# python3 practica2.py archivo -a base64 -c -o salida
Descifrado Uso: 
# python3 practica2.py archivo -a base64 -d -o salida
'''
def base64_encode(data):
    base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    encoded = []

    for i in range(0, len(data), 3):
        chunk = data[i:i+3]

        padding = 3 - len(chunk)

        if len(chunk) < 3:
            chunk += b"\x00" * padding

        buffer = (chunk[0] << 16) | (chunk[1] << 8) | chunk[2]

        idx1 = (buffer >> 18) & 0x3F
        idx2 = (buffer >> 12) & 0x3F
        idx3 = (buffer >> 6) & 0x3F
        idx4 = buffer & 0x3F

        encoded.append(base64_table[idx1])
        encoded.append(base64_table[idx2])

        if padding == 2:
            encoded.append("=")
            encoded.append("=")
        elif padding == 1:
            encoded.append(base64_table[idx3])
            encoded.append("=")
        else:
            encoded.append(base64_table[idx3])
            encoded.append(base64_table[idx4])

    return "".join(encoded).encode("ascii")


def base64_decode(data):
    base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    decoded_bytes = bytearray()

    if isinstance(data, bytes):
        data = data.decode("ascii")

    data = "".join(data.split())

    if len(data) % 4 != 0:
        raise ValueError("La entrada debe tener longitud múltiplo de 4")

    for i in range(0, len(data), 4):
        chunk = data[i:i+4]

        values = []
        padding = 0

        for c in chunk:
            if c == "=":
                values.append(0)
                padding += 1
            else:
                pos = base64_table.find(c)
                if pos == -1:
                    raise ValueError(f"Carácter inválido en Base64: {c}")
                values.append(pos)

        # reconstruir 24 bits
        buffer = (
            (values[0] << 18) |
            (values[1] << 12) |
            (values[2] << 6)  |
            values[3]
        )

        byte1 = (buffer >> 16) & 0xFF
        byte2 = (buffer >> 8) & 0xFF
        byte3 = buffer & 0xFF

        decoded_bytes.append(byte1)

        if padding < 2:
            decoded_bytes.append(byte2)

        if padding < 1:
            decoded_bytes.append(byte3)

    return bytes(decoded_bytes)

def main():
    if len(sys.argv) < 5:
        print("Uso:")
        print("python3 practica2.py archivo -a algoritmo -c|-d -k1 clave1 [-k2 clave2] -o salida")
        return

    filename = sys.argv[1]
    algoritmo = None
    cifrar = False
    descifrar = False
    key1 = None
    key2 = None
    output = None

    i = 2
    while i < len(sys.argv): 
        arg = sys.argv[i]

        if arg == "-a":
            algoritmo = sys.argv[i+1]
            i += 2
        elif arg == "-c":
            cifrar = True
            i += 1
        elif arg == "-d":
            descifrar = True
            i += 1
        elif arg == "-k1":
            key1 = int(sys.argv[i+1])
            i += 2
        elif arg == "-k2":
            key2 = int(sys.argv[i+1])
            i += 2
        elif arg == "-o":
            output = sys.argv[i+1]
            i += 2
        else:
            i += 1
    try:
         # READ
        with open(filename, "rb") as f:
            data = f.read()

        # PROCESAR
        if algoritmo == "cesar":
            ans = cesar(data, key1, cifrar)

        elif algoritmo == "decimado":
            ans = decimado(data, key1, cifrar)

        elif algoritmo == "afin":
            ans = afin(data, key1, key2, cifrar)

        elif algoritmo == "fuerza_bruta_decimado":
            ans = fuerza_bruta_decimado(data)

        elif algoritmo == "fuerza_bruta_afin":
            ans = fuerza_bruta_afin(data)

        elif algoritmo == "base64":
            ans = base64(data, cifrar)

        else:
            print("Algoritmo no válido")
            return

        # WRITE
        if output:
            with open(output, "wb") as f:
                f.write(ans)
            print("Archivo guardado en:", output)

    except FileNotFoundError:
        print("ERROR: archivo no encontrado")

if __name__ == "__main__":
    main()