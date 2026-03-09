'''
Retornar el inverso de 'a' módulo 256, si existe.
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

print(inversos256)