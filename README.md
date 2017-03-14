Padding Oracle Attacks

## Instruction

* Test: `py.test -x --pdb --ignore=my-venv poattack.py`
* 

## Installation

* https://github.com/mw866/stream-cipher/blob/master/README.md

## Reference

* Tutorial of Padding Oracle Attack: 
- https://grymoire.wordpress.com/2014/12/05/cbc-padding-oracle-attacks-simplified-key-concepts-and-pitfalls/
- http://robertheaton.com/2013/07/29/padding-oracle-attack/
- https://www.youtube.com/watch?v=XOTiymUDNP4
- https://github.com/mpgn/Padding-oracle-attack

## Troubleshooting

* Mistakenly guessed P_prime[-1] to 'x\01' when actually it is 'x\0f'.

Solutions:
Toggle P_prime[-2] by XOR C0_prime[-2] ^ 01, then see if it breaks the decrypt(). If it does, it means the P_prime[-1] is not actually x\01.
See "Backtrack" in https://blog.skullsecurity.org/2013/padding-oracle-attacks-in-depth

## Performance
o. Blocks: 2     Time:0.11422085762s