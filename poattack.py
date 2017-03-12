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
    for pad in xrange(po.block_length): #interate through the each bytes in the block        
        if pad == 0:             
            #[TOOD] Add the case where pad =0 add a new block
            continue
        for p_prime in xrange(256):   #interate through all the possible guesses         
            Pad = ''.join([chr(pad) for k in xrange(pad)])
            padded_p_prime = chr(p_prime)+chr(0)*(pad-1)
            C0_prime_lastbytes = xor(padded_p_prime, Pad)
            C0_prime_lastbytes = xor(C0_prime_lastbytes, C0[-pad:])
            C0_prime = C0[:-pad] + C0_prime_lastbytes
            if po.decrypt(C0_prime + C1):
                pudb.set_trace() 
                c0, c0_prime = ord(C0[-pad]), ord(C0_prime[-pad])
                i = p_prime ^ c0_prime
                p = c0 ^ i
                P = chr(p) + P
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
