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
cond = True
pub_key_list = []
sig_list = []
param_key = DSA.import_key(key_pem)
param = [param_key.p, param_key.q,param_key.g] 
message = b'CSCI301 Contemporary topic in security'

input_M = input("Number of Signatures (M): ")
input_N = input("Number of Public key (N): ")

# to check N is equal or greater than M
while (cond):
	if input_N < input_M or int(input_N) > 3:
		print("Number of public key (N) must be equal to or greater than M / public key is limited to 3")
		input_M = input("Number of Signatures (M): ")
		input_N = input("Number of Public key (N): ")
	else: 
		cond = False

# write public key(s) to 'scriptPubkey.txt
f = open("scriptPubKey.txt", "w")
#pub_key_list.append(1)
for i in range(1, int(input_N)+1):
    globals()['key%s' % i]  = DSA.generate(1024, domain= param)
    pub_key_list.append(globals()['key%s' % i].y)
    f.write(hex(pub_key_list[i-1]) + '\n')

f.write(input_N)

f.close()

# write signature(s) to scriptSig.txt'
f = open("scriptSig.txt", "wb")
f.write(b'1\n') # OP_1
for i in range(1, int(input_M)+1):
	hash_obj = SHA256.new(message)
	signer = DSS.new(globals()['key%s' % i], 'fips-186-3')
	globals()['signature%s' % i] = signer.sign(hash_obj)
	sig_list.append(globals()['signature%s' % i])
	f.write(binascii.hexlify(sig_list[i-1]) + b'\n')


f.close()
	
# store the rest of the parameters into key.pem
#f = open('key.pem', 'wb')
#f.write(key1.publickey().export_key())
#f.close()

print('scriptPubKey.txt generated!')
print('scriptSig.txt generated!')

