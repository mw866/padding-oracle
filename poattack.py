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
    # [Completed]: Implement padding oracle attack for 2 blocks of messages.
    # Naming Convention: Uppercase: Bytes in an string; Lowercase: Byte in an integer
    
    I = ''.join(chr(0) * po.block_length)
    C0_prime = C0
    # print '=== Launching Oracle Attacks ==='
    #interate through the each bytes in the block
    for pad in xrange(1, po.block_length + 1): 
        # XOR C0_prime[-pad+1:] with I[-pad+1:]
        C0_prime = C0_prime[:-pad] + xor(I[-pad:], chr(pad)*pad) 

        #interate through all the possible guesses
        for c0_prime in xrange(256):        
            #skip the original value    
            if ord(C0_prime[-pad]) == c0_prime: continue 

            # Guessing c0_prime at C0_prime[-pad]
            C0_prime_list = list(C0_prime)
            C0_prime_list[-pad] = chr(c0_prime)
            C0_prime = ''.join(C0_prime_list)

            P_prime = C0_prime + C1
            if po.decrypt(P_prime):
                # To ensure the guessed last byte is indeed \x01, rather than \x01, \x02 etc... 
                if pad == 1:
                    C0_prime_list_test = list(C0_prime)
                    C0_prime_list_test[-2] = chr(ord(C0_prime_list_test[-2]) ^ 1)
                    C0_prime_test = ''.join(C0_prime_list_test) 
                    P_prime_test = C0_prime_test + C1
                    if not po.decrypt(P_prime_test): continue
                I_list = list(I)
                I_list[-pad] = chr(c0_prime ^ pad)
                I = ''.join(I_list)

                p = ord(I[-pad]) ^ ord(C0[-pad])
                P = chr(p) + P 
                # print pad, '\t',c0_prime,'\t', p, '\t', list(P),'\t'
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
    # WIP: Implement padding oracle attack for arbitrary length message.
    P = ""
    for i in xrange(nblocks-1):
        ctx_2blocks = ctx_blocks[i] + ctx_blocks[i+1]
        p = po_attack_2blocks(po, ctx_2blocks)
        P = P + p
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
        po = PaddingOracle(msg_len=i)
        ctx = po.setup()
        msg = po_attack(po, ctx)
        assert po.test(msg), "Failed 'po_attack' for msg of length={}".format(i)
        print 'Success i=',i # [TODO] To delete

def test_poserver_attack():
    # You may want to put some print statement in the code to see the
    # progress. This attack might 10.218.176.10take upto an hour to complete. 

    po = PaddingOracleServer()
    ctx = po.ciphertext()
    msg = po_attack(po, ctx)
    print msg

test_po_attack() #[TODO To be commented