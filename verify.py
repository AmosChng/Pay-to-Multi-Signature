from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii

key_pem = "-----BEGIN PUBLIC KEY-----\n\
MIIBtjCCASsGByqGSM44BAEwggEeAoGBAMru3+fqTHjUXRjgmXBzxtEMXceRdXVK\n\
SxQYWEb2zHFkc8MVBxE41Cgv9sVsNTFI9VsIlVrSyXHeUJ6LKznZOjC5qWEawR9E\n\
bBpCZlc0uDjc8NbQ9MFQkgw0TmERn/Xg1SjY8z6aaVR8BwT6/Bt/63AxdOmH9UPK\n\
ullMaqDruzplAhUAmzGsd2tN44X8WEdvdK+RKIj/SasCgYAmyasijKGmEDEJZrR0\n\
TPDxPFas8MlyPNSYj4zokNm5JG/2DsDoAyVlGQkRgEjET3a15OQazLRX2FC9hRZI\n\
XH87TLH2XyTzm9SzBBmKcfF8r/kyoWfNkDq6kU27RWZO6oVPZqrNi5T+ncS5amnM\n\
AUiij85K0LaIYPxczZL1s2qGhAOBhAACgYAlD9gc7GKnLQ4N4yfZrAdoAxkXpNSC\n\
xN9d8FUsuADHjgMMybDKOGyELdLn5dDOFRZd4qnykEndEuM5hZqBZPWHBj3AJ5Xd\n\
XXnWzMay1oatMHKPs1mi1wVKgtsk2GZu/OEJm2y/lEZfNUTA6jc/Q9Jqiemh2dOm\n\
AOf/PuTH08Td3Q==\n\
-----END PUBLIC KEY-----\n\
"

param_key = DSA.import_key(key_pem)	

M = 0
N = 0
sig_list = []
pubkey_list = []
message = b'CSCI301 Contemporary topic in security'

with open('scriptSig.txt') as f:
	lines = f.read()
	stack = (lines.strip()).split('\n') # push signatures into stack

for i in range(0, len(stack)):
	M = M + 1 # OP_2
	
stack.append(M-1) # push M into stack (M-1 because OP_1 is inside list)
f.close()


with open('scriptPubKey.txt') as f:
	lines = f.read()
temp_list = str(lines.strip()).split('\n') # for temporary storing 

for i in range(0, len(temp_list)):
	stack.append(temp_list[i]) # push public keys into stack

# not needed to push OP_3 into stack as N is already wrote into 'scriptPubkey.txt in DSA.py

f.close()
print('======================STACK AFTER PUSHING=========================')
print(stack)
print('==================================================================')

#start of CHECKMULTISIG...

for i in range(0, int(stack[-1])+1):
	pubkey_list.append(stack.pop()) # pop public keys from stack, FILO

for i in range(0, int(stack[-1])+1):
	sig_list.append(stack.pop())  # pop signatures from stack, FILO

stack.pop()
print('======================STACK AFTER POPPING=========================')
print(stack)
print('==================================================================')

pubkey_list.pop(0)
sig_list.pop(0)

# verify public keys with signature

hash_obj = SHA256.new(message)
for i in range(0, len(sig_list)):
	for j in range(0, len(pubkey_list)):
		try:
			tup = [int(pubkey_list[j], 16), param_key.g, param_key.p, param_key.q]
			pub_key = DSA.construct(tup)
			verifier = DSS.new(pub_key, 'fips-186-3')
			verifier.verify(hash_obj, binascii.unhexlify(sig_list[i]))
			print("Verifying pubKey"+ str(j+1) + " with sig" + str(i+1) + "...")
			stack = True # valid
			print(stack)

		except ValueError:
			print("Verifying pubKey"+ str(j+1) + " with sig" + str(i+1) + "...")
			print('X') # not valid

