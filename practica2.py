import argparse
'''
Este código me lo tome de:
https://whatisnote.eokultv.com/files/169507-how-to-master-file-identification-with-magic-bytes-in-python-314-a-forensic-deep-dive
'''
def get_magic_bytes(filepath, num_bytes=8):
    try:
        with open(filepath, 'rb') as f:
            magic_bytes = f.read(num_bytes)
        return magic_bytes
    except FileNotFoundError:
        return None

def identify_file_type(magic_bytes):
    signatures = {
        '89504e47': 'PNG image',
        '47494638': 'GIF image',
        'ffd8ffe0': 'JPEG image',
        '504b0304': 'ZIP archive'
    }
    
    magic_hex = magic_bytes.hex()
    for signature, file_type in signatures.items():
        if magic_hex.startswith(signature):
            return file_type
    return 'Unknown file type'

def analyze_file(filepath):
    magic_bytes = get_magic_bytes(filepath)
    if magic_bytes:
        file_type = identify_file_type(magic_bytes)
        print(f'File: {filepath}')
        print(f'Magic Bytes: {magic_bytes.hex()}')
        print(f'Identified File Type: {file_type}')
    else:
        print('File not found.')

def inspect(b):
    print("bytes: ", b)
    print("int: ",list(b))
    print("hex: ", b.hex())
    print("\n")

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

inversos256 = {}
for i in range(1,256,2):
    inversos256[i] = getInv(i)

# Esto Hardcodeado es para analizar
file_path_1 = 'files/file1.lol'
file_path_2 = 'files/file2.lol'
file_path_3 = 'files/file3.lol'
file_path_4 = 'files/file4.lol'

inspect(get_magic_bytes(file_path_1)) # FILE1 -> MP4
inspect(get_magic_bytes(file_path_2))
inspect(get_magic_bytes(file_path_3))
inspect(get_magic_bytes(file_path_4)) # FILE4 -> JPG

'''
Cifrado de César (también decifrador con -k) ^^
'''
def cesar(data, k, cifrar):
    if not cifrar:
        k = k * -1
    return bytes((b + k) % 256 for b in data)

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("filename", help="Ruta del archivo.")
    parser.add_argument("-o", "--output", help="Ruta del archivo de salida.")

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-c', '--cifrar',   action='store_true')
    group.add_argument('-d', '--decifrar', action='store_true')

    parser.add_argument('-a', '--algoritmo', choices= ['cesar'])
    parser.add_argument('-k1', '--key1', type=int)

    arg = parser.parse_args()

    try:
        # READ
        with open(arg.filename, "rb") as f:
            data = f.read()

        # CIFRAR y DECIFRAR
        if arg.algoritmo == 'cesar':
            ans = cesar(data, arg.key1, arg.cifrar)

        # WRITE
        with open(arg.output, "wb") as f:
            f.write(ans)

    except FileNotFoundError:
        print("ERROR")



if __name__ == "__main__":
    main()