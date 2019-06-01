from charm.toolbox.pairinggroup import ZR,G1,pair
from charm.toolbox.hash_module import Hash
import pickle
import base64

debug = False

class IBME():

    def __init__(self, groupObj=None):
        if groupObj is None:
            from charm.toolbox.pairinggroup import PairingGroup
            groupObj = PairingGroup('SS512', secparam=512)  
        global group
        group = groupObj
        mask = 'ed27dbfb02752e0e16bc4502d6c732bc5f1cc92ba19b2d93a4e95c597ca42753e93550b52f82b6c13fb8cc0c2fc64487'
        self._mask = bytes.fromhex(mask)
        
    def setup(self):
        r, s, P = group.random(ZR), group.random(ZR), group.random(G1)
        P0 = r * P

        pk = (P, P0)
        sk = (r, s)
        if(debug):
            print("Public parameters...")
            group.debug(pk)
            print("Secret parameters...")
            group.debug(sk)
        return (pk, sk)

    def H(self, X):
        return group.hash(X, G1)

    def H_prime(self, X):
        # Both H and H' are computed from the same method group.hash()
        # In order to make them different, we apply a fixed mask to the
        # inputs of H'
        X = bytes([ a ^ b for (a,b) in zip(X.encode(), self._mask) ])
        return group.hash(X, G1)
    
    def skgen(self, sk, S):  
        (_, s) = sk      
        ek = s * self.H_prime(S)

        if(debug):
            print("Key for attrs S '{}' => {}".format(S, ek))
        return ek

    def rkgen(self, sk, R):  
        (r, s) = sk       
        H_R = self.H(R) 
        dk1 = r * H_R
        dk2 = s * H_R
        dk3 = H_R
        
        dk = (dk1, dk2, dk3)

        if(debug):
            print("Key for attrs R '{}' => {}".format(R, dk))
        return dk
        
    
    def encrypt(self, pk, R, ek_S, M): # check length to make sure it is within n bits

        (P, P0) = pk

        u = group.random(ZR)
        t = group.random(ZR)
        
        T = t * P
        U = u * P

        H_R = self.H(R) 
        k_R = pair(H_R, u * P0)

        k_S = pair(H_R, T + ek_S)

        enc_k_R = group.serialize(k_R)[2:-1]
        enc_k_S = group.serialize(k_S)[2:-1]

        V = bytes([ a ^ b ^ c for (a,b,c) in zip(M, enc_k_R, enc_k_S) ])

        C = (T, U, V)

        if(debug):
            print('\nEncrypt...')
            print('T   =>', T)
            print('u => %s' % u)
            print('U => %s' % U)
            print("V'  =>" % V)
            print('enc_k_R => %s' % enc_k_R)
            print('enc_k_S => %s' % enc_k_S)
            #group.debug(C)
        return C
    
    def decrypt(self, pk, dk, S, C):

        (dk1, dk2, dk3) = dk
        (T, U, V) = C
        
        k_R = pair(dk1, U)

        H_prime_S = self.H_prime(S)
   
        k_S = pair(dk3, T) * pair(H_prime_S, dk2)

        enc_k_R = group.serialize(k_R)[2:-1]
        enc_k_S = group.serialize(k_S)[2:-1]
        
        M = bytes([ a ^ b ^ c for (a,b,c) in zip(V, enc_k_R, enc_k_S) ])

        if(debug):
            print('\nDecrypt....')
            print('T   =>', T)
            print('U   =>', U)
            print('V   =>', V)
            print("M'  =>", M)
        return M

    def serialize_ciphertext(self, C):
        T, U, V = C
        T = base64.b64decode(group.serialize(T)[2:])
        U = base64.b64decode(group.serialize(U)[2:])
        return pickle.dumps((T, U, V))

    def deserialize_ciphertext(self, bitstring):
        T, U, V = pickle.loads(bitstring)
        T = group.deserialize(b'1:'+base64.b64encode(T))
        U = group.deserialize(b'1:'+base64.b64encode(U))
        return (T, U, V)

    def serialize_setup(self, S):
        pk, sk = S
        return pickle.dumps(tuple(group.serialize(x) for x in pk+sk))

    def deserialize_setup(self, bitstring):
        pieces = pickle.loads(bitstring)
        P, P0, r, s = tuple(group.deserialize(p) for p in pieces)
        pk = (P, P0)
        sk = (r, s)
        return pk, sk
        
    def serialize_tuple(self, input):
        return pickle.dumps(tuple(group.serialize(x) for x in input))

    def deserialize_tuple(self, bitstring):
        pieces = pickle.loads(bitstring)
        return tuple(group.deserialize(p) for p in pieces)


if __name__ == "__main__":
    debug = True
    from charm.toolbox.pairinggroup import PairingGroup
    group = PairingGroup('SS512', secparam=512)    
    ME = IBME(group)
    (master_public_key, master_secret_key) = ME.setup()
    R = 'attribute 1, attribute 2'
    S = 'attribute 3, attribute 4'
    dk = ME.rkgen(master_secret_key, R)
    ek = ME.skgen(master_secret_key, S)
    msg = b"hello world!!!!!"
    cipher_text = ME.encrypt(master_public_key, R, ek, msg)

    msg_prime = ME.decrypt(master_public_key, dk, S, cipher_text)
    assert msg == msg_prime

    S2 = 'attribute 5'
    msg_2 = ME.decrypt(master_public_key, dk, S2, cipher_text)
    assert msg != msg_2

    import timeit

    setup = '''
from __main__ import IBME
from charm.toolbox.pairinggroup import PairingGroup,pair
from charm.toolbox.pairinggroup import ZR,G1,pair
group = PairingGroup('SS512', secparam=512)    
ME = IBME(group)
(master_public_key, master_secret_key) = ME.setup()
R = 'attribute 1, attribute 2'
S = 'attribute 3, attribute 4'
dk = ME.rkgen(master_secret_key, R)
ek = ME.skgen(master_secret_key, S)
msg = b"hello world!!!!!"
    '''
    debug = False
    iters = 10
    repetitions = 50
    print("\n=====")
    print("Benchmarking IB-ME...{} iters, {} repetitions".format(iters, repetitions))
    encryption = 'cipher_text = ME.encrypt(master_public_key, R, ek, msg)'
    timer = timeit.Timer(encryption, setup=setup)
    print('Encryption time (ms):')
    timings = [time/iters for time in timer.repeat(repetitions, iters)]
    print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))

    setup = setup + "\n" + encryption

    decryption = 'ME.decrypt(master_public_key, dk, S, cipher_text)'
    timer = timeit.Timer(decryption, setup=setup)
    print('Decryption time (ms):')
    timings = [time/iters for time in timer.repeat(repetitions, iters)]
    print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))

    pairing = 'pair(dk[0], ek)'
    timer = timeit.Timer(pairing, setup=setup)
    print('Pairing time (ms):')
    timings = [time/iters for time in timer.repeat(repetitions, iters)]
    print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))

    expo = "master_secret_key[0] * ek"
    timer = timeit.Timer(expo, setup=setup)
    print('Expo time (ms):')
    timings = [time/iters for time in timer.repeat(repetitions, iters)]
    print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))

    ra = "group.random(ZR)"
    timer = timeit.Timer(ra, setup=setup)
    print('Random time (ms):')
    timings = [time/iters for time in timer.repeat(repetitions, iters)]
    print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))

    h = "ME.H(R)"
    timer = timeit.Timer(h, setup=setup)
    print('H time (ms):')
    timings = [time/iters for time in timer.repeat(repetitions, iters)]
    print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))

    h2 = "ME.H_prime(R)"
    timer = timeit.Timer(h2, setup=setup)
    print("H' time (ms):")
    timings = [time/iters for time in timer.repeat(repetitions, iters)]
    print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))

    
    setupp = "(master_public_key, master_secret_key) = ME.setup()"
    timer = timeit.Timer(setupp, setup=setup)
    print("setup time (ms):")
    timings = [time/iters for time in timer.repeat(repetitions, iters)]
    print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))


    rkgen = "dk = ME.rkgen(master_secret_key, R)"
    timer = timeit.Timer(setupp, setup=setup)
    print("rkgen time (ms):")
    timings = [time/iters for time in timer.repeat(repetitions, iters)]
    print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))


    setupp = "ek = ME.skgen(master_secret_key, S)"
    timer = timeit.Timer(setupp, setup=setup)
    print("skgen time (ms):")
    timings = [time/iters for time in timer.repeat(repetitions, iters)]
    print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))

    



         