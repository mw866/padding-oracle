from paddingoracle import PaddingOracle, PaddingOracleServer, xor
import pudb

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
    C0, C1 = list(split_into_blocks(ctx, po.block_length))
    P = ''
    # [WIP]: Implement padding oracle attack for 2 blocks of messages.
    # Convesion: Uppercase: Bytes in an string; Lowercase: Byte in an integer
    
    '''    
    # C0_prime, C1_prime = C0, C1
    for c0_prime in xrange(256):
        pad = 1
        if ord(C0[-pad]) == c0_prime: continue #skip the original value
        C0_prime = C0[:-pad] + chr(c0_prime)
        if po.decrypt(C0_prime + C1) :
            i = c0_prime ^ pad
            p = i ^ ord(C0[-pad])
            print p
            pudb.set_trace()
            break
    '''
    I = ''.join(chr(0) * po.block_length)
    C0_prime = C0
    print '=== Launching Oracle Attacks ==='
    for pad in xrange(1, po.block_length + 1): #interate through the each bytes in the block        

        # if pad == 0:             
        #     #[TODO] Add the case where pad =0 add a new block
        #     continue

        # XOR C0_prime[-pad+1:] with I[-pad+1:]
        # C0_prime = C0_prime[:-(pad-1)] + ''.join([chr(ord(c0)+1) for c0 in C0_prime[-(pad-1):]])
        C0_prime = C0_prime[:-pad] + xor(I[-pad:], chr(pad)*pad) # Alternatively

        for c0_prime in xrange(256):   #interate through all the possible guesses         
            if ord(C0_prime[-pad]) == c0_prime: continue #skip the original value
            # C0_prime = C0[:-pad] + chr(c0_prime) + C0[-pad+1:]

            # Guessing c0_prime at C0_prime[-pad]
            C0_prime_list = list(C0_prime)
            C0_prime_list[-pad] = chr(c0_prime)
            C0_prime = ''.join(C0_prime_list)

            if po.decrypt(C0_prime + C1):
                I_list = list(I)
                I_list[-pad] = chr(c0_prime ^ pad)
                I = ''.join(I_list)

                p = ord(I[-pad]) ^ ord(C0[-pad])
                P = chr(p) + P 
                # pudb.set_trace()
                print pad, '\t',c0_prime,'\t', p, '\t', list(P)
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
    # TODO: Implement padding oracle attack for arbitrary length message.


    
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
        po = PaddingOracle(msg_len=i)
        ctx = po.setup()
        msg = po_attack(po, ctx)
        assert po.test(msg), "Failed 'po_attack' for msg of length={}".format(i)

def test_poserver_attack():
    # You may want to put some print statement in the code to see the
    # progress. This attack might 10.218.176.10take upto an hour to complete. 

    po = PaddingOracleServer()
    ctx = po.ciphertext()
    msg = po_attack(po, ctx)
    print msg

test_po_attack_2blocks() #[TODO To be commented