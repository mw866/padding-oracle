from paddingoracle import PaddingOracle, PaddingOracleServer, xor
import pudb
import time


'''
## Variables
C1: Ciphertext Block 0
C1_prime: C1 guess 
c1_prime: C1 byte guess 
C2: Ciphertext Block 1
P_prime: Plaintext guess 
p: Correctly guessed byte in P(laintext)
P: Correctly guessed Plaintext i.e. msg
I: Intermediary State i.e. output of decrypt()

Naming Convention based on: http://robertheaton.com/2013/07/29/padding-oracle-attack/
'''

def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]
    
def po_attack_2blocks(po, ctx):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext generated using po.setup()
    Don't unpad the message.
    """
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    C1, C2 = list(split_into_blocks(ctx, po.block_length))
    P = ''
    # [Completed]: Implement padding oracle attack for 2 blocks of messages.
    # Naming Convention: Uppercase: Bytes in an string; Lowercase: Byte in an integer
    
    I = ''.join(chr(0) * po.block_length)
    C1_prime = C1
    print '--- Launching Padding Oracle Attacks ---'
    print 'pad\tc1_prime\tp\tP\t'
    #interate through the each bytes in the block
    for pad in xrange(1, po.block_length + 1): 
        # XOR C1_prime[-pad+1:] with I[-pad+1:]
        C1_prime = C1_prime[:-pad] + xor(I[-pad:], chr(pad)*pad) 

        #Interate through all the possible guesses
        for c1_prime in xrange(256):        
            #Skip the original value    
            if ord(C1_prime[-pad]) == c1_prime: continue 

            # Guessing c1_prime at C1_prime[-pad]
            C1_prime_list = list(C1_prime)
            C1_prime_list[-pad] = chr(c1_prime)
            C1_prime = ''.join(C1_prime_list)

            P_prime = C1_prime + C2
            if po.decrypt(P_prime):
                # Ensure the guessed last byte is indeed \x01, rather than \x01, \x02 etc... 
                if pad == 1:
                    C1_prime_list_test = list(C1_prime)
                    C1_prime_list_test[-2] = chr(ord(C1_prime_list_test[-2]) ^ 1)
                    C1_prime_test = ''.join(C1_prime_list_test) 
                    P_prime_test = C1_prime_test + C2
                    if not po.decrypt(P_prime_test): continue
                # Derive P based on I and C1
                I_list = list(I)
                I_list[-pad] = chr(c1_prime ^ pad)
                I = ''.join(I_list)

                p = ord(I[-pad]) ^ ord(C1[-pad])
                P = chr(p) + P 
                print '\n', pad, '\t',c1_prime,'\t', p, '\t', list(P),'\t'
                break

    return P

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext generated using po.setup()
    You don't have to unpad the message.
    """

    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    # [Completed]: Implement padding oracle attack for arbitrary length message.
    P = ""
    for i in xrange(nblocks-1):
        print '\n=== Block: {}/{} ==='.format(i, nblocks)
        t_start = time.time()

        # Attack block by block
        ctx_2blocks = ctx_blocks[i] + ctx_blocks[i+1]
        p = po_attack_2blocks(po, ctx_2blocks)
        P = P + p 

        t_end = time.time() 
        print 'Time: {}s'.format(t_end-t_start) 
    return P

    
################################################################################
##### Tests
################################################################################

def test_po_attack_2blocks():
    for i in xrange(1, 16):
        po = PaddingOracle(msg_len=i)
        ctx = po.setup()
        msg = po_attack_2blocks(po, ctx)
        assert po.test(msg), "Failed 'po_attack_2blocks' for msg of length={}".format(i)

def test_po_attack():
    for i in xrange(1000):
        t_start = time.time()

        po = PaddingOracle(msg_len=i)
        ctx = po.setup()
        msg = po_attack(po, ctx)
        assert po.test(msg), "Failed 'po_attack' for msg of length={}".format(i)
        
        t_end = time.time() # Added
        t = t_end-t_start   # Added
        if i !=0: print 'Message Length: {}\t Time: {}s\t Time/Byte: {}'.format(i, t, t/float(i)) # Added

def test_poserver_attack():
    # You may want to put some print statement in the code to see the
    # progress. This attack might take upto an hour to complete. 

    po = PaddingOracleServer()
    ctx = po.ciphertext()
    msg = po_attack(po, ctx)
    print msg

# test_poserver_attack() # For running tests

# Plain text:
# {"msg": "Congrats you have cracked a secret message!", "name": "Padding Oracle"}