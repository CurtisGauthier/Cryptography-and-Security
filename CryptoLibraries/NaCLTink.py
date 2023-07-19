#!/usr/bin/env python
"""
COMP3109 final project. By David Barrera

With contributions from Discord users:
clark
Always
Ynnad00
Kushaforei
Breezy
Andyimo
EnderTheNetrunner
nicman
"""
import nacl
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, SealedBox, Box
from nacl.signing import SigningKey, VerifyKey
import nacl.encoding
import nacl.hash
from nacl.hash import blake2b
import tink
from tink import aead
from tink import tink_config
from tink import hybrid
from tink import mac
from tink import signature

def generateSecretKeyNacl():
    """
    Generates a random symmetric key using nacl
    
    Returns:
        key (bytes)
    """

    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    return key


def generateSecretKeyTink():
    """
    Generates a random symmetric key using Tink.

    Notes:
        Use the AEAD primitive.
        Use the AES256_GCM key template
    Returns:
        keyset_handle (KeysetHandle)
    """
    aead.register()

    keyTemplate = aead.aead_key_templates.AES128_EAX
    keysetHandle = tink.new_keyset_handle(keyTemplate)

    return keysetHandle

def aeadEncryptNacl(key, message, associated_data, nonce):
    """
    Encrypts plaintext string "message" and associate data "aad" using key and a 24 byte nonce. Uses AEAD
    
    Notes: this function should return a ciphertext to be used as the first parameter of aeadDecryptNacl() below. 
    Parameters:
        key (bytes)
        message (string)
        associated_data (bytes)
        nonce (bytes)
        
    Returns:
        ciphertext (bytes)
    """
    msg = bytes(message, encoding = 'utf8')

    box = nacl.secret.SecretBox(key)
    encrypted = box.encrypt(associated_data + msg, nonce)

    return encrypted.ciphertext


def aeadDecryptNacl(ciphertext, associated_data, key, nonce):
    """
    Decrypts a ciphertext using associated_data, key and nonce
    
    Parameters:
        ciphertext (bytes)
        associated_data (bytes)
        key (bytes)
        nonce (bytes)
    Returns:
        message (string)
    """
    box = nacl.secret.SecretBox(key)
    ptext = box.decrypt(ciphertext, nonce)

    return ptext[len(associated_data):].decode("utf8")


def aeadEncryptTink(keyset_handle, message, associated_data):
    """
    Encrypts plaintext message and associated data using XCHACHA20-POLY1305 and a provided keyset handle.

    Notes: 
        Function must ensure that the keyset handle is compatible with XCHACHA20-POLY1305. Should return a ciphertext that can be passed as the first parameter of aeadDecryptTink() below. 
    Parameters:
        keyset_handle (KeysetHandle)
        message (string)
        associated_data (bytes)
    Returns:
        ciphertext (bytes)
    """
    aead.register()
    aead_primitive = keyset_handle.primitive(aead.Aead)
    ciphertext = aead_primitive.encrypt(bytes(message, encoding = "utf8"), associated_data)
    return ciphertext

def aeadDecryptTink(ciphertext, associated_data, keyset_handle):
    """
    Decrypts a ciphertext using the keyset handle and associated data

    Parameters:
        ciphertext (bytes)
        associated_data (bytes)
        keyset_handle (KeysetHandle)
    Returns:
        plaintext (string)
    """
    aead_primitive = keyset_handle.primitive(aead.Aead)
    ptext = aead_primitive.decrypt(ciphertext, associated_data)

    ptext = ptext.decode("utf8")

    return ptext
    
def generateKeyPairNacl():
    """
    Uses NaCl to generate a public/private key pair

    Returns: 
        Returns tuple of Curve25519 keys:
            privkey (PrivateKey)
            pubkey (PublicKey)
    """
    privKey = PrivateKey.generate()
    pubKey = privKey.public_key

    return (privKey, pubKey)




def generateHybridEncryptionKeyPairTink():
    """
    Uses Tink to generate a keypair suitable for hybrid encryption
    
    Notes:
        Keys must use the ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256 hybrid key template
    Returns:
        Tuple of keyset handles 
            private_keyset_handle (KeysetHandle)
            public_keyset_handle (KeysetHandle)
    """
    hybrid.register()
    private_keyset_handle = tink.new_keyset_handle(hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256)
    public_keyset_handle = private_keyset_handle.public_keyset_handle()

    return (private_keyset_handle, public_keyset_handle)

def hybridEncryptNacl(message, pubkey):
    """
    Uses the public key to encrypt a random symmetric key, and then encrypts message using that symmetric key. MUST NOT ENCRYPT USING PUBKEY DIRECTLY!
    
    Notes: The returned ciphertext and encrypted_symmetric_key should be compatible with the hybridDecryptNacl() below. 
    Parameters:
        message (string)
        pubkey (PublicKey)
    Returns:
        Tuple containing:
            ciphertext (bytes)
            encrypted_symmetric_key (bytes)
    """
    
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    box = nacl.secret.SecretBox(key)
    ciphertext = box.encrypt(bytes(message, encoding='utf8'))


    box2 = SealedBox(pubkey)
    symmKey = box2.encrypt(key)



    return (ciphertext, symmKey)


def hybridDecryptNacl(ciphertext, encrypted_key, privkey):
    """
    Uses the private key to first decrypt the shared symmetric key (generated in hybridEncryptNacl). Uses the symmetric key to decrypt the ciphertext. 
    
    Parameters:
        ciphertext (bytes)
        encrypted_symmetric_key (bytes)
        privkey (PrivateKey)
    
    Returns plaintext (string)
    """
    unsealedBox = SealedBox(privkey)
    symmKey = unsealedBox.decrypt(encrypted_key)

    box2 = nacl.secret.SecretBox(symmKey)
    decrypted = box2.decrypt(ciphertext)

    

    return decrypted.decode("utf8")

def hybridEncryptTink(message, associated_data, public_keyset_handle):
    """
    Uses Tink to perform hybrid encryption on a plaintext message and associated data, and uses a public keyset handle to obtain the public key to use. 
    
    Notes: The ciphertext should be compatible as the first parameter of the hybridDecryptTink() function below.
    Parameters:
        message (string)
        associated_data (bytes)
        public_keyset_handle (KeysetHandle)
    Returns:
        ciphertext (bytes)
    """
    encrypt = public_keyset_handle.primitive(hybrid.HybridEncrypt)

    ciphertext = encrypt.encrypt(bytes(message, encoding = "utf8"), associated_data)

    return ciphertext

def hybridDecryptTink(ciphertext, associated_data, private_keyset_handle):
    """
    Decrypts ciphertext using private key. Requires passing associated_data for authentication. 

    Parameters:
        ciphertext (bytes)
        associated_data (bytes)
        private_keyset_handle (KeysetHandle)
    Returns:
        plaintext (string)
    """
    decrypt = private_keyset_handle.primitive(hybrid.HybridDecrypt)

    ptext = decrypt.decrypt(ciphertext, associated_data)

    return ptext.decode("utf8")


def generateSignatureKeypairNacl():
    """
    Generates a signing key and a verification key using Nacl

    Returns: 
        Tuple of keys
            sigkey (SigningKey)
            verifykey (VerifyKey)
    """
    signKey = SigningKey.generate()
    verifyKey = signKey.verify_key

    return (signKey, verifyKey)

def generateSignatureKeypairTink():
    """
    Generates a signing key and verification key using Tink.
    
    Notes: must use the ECDSA_P384 signature key template
    Returns:
        Tuple of keyset handles 
            signing_keyset_handle (KeysetHandle)
            verify_keyset_handle (KeysetHandle)
    """
    signature.register()

    signing_keyset_handle = tink.new_keyset_handle(signature.signature_key_templates.ECDSA_P384)

    verify_keyset_handle = signing_keyset_handle.public_keyset_handle()

    return (signing_keyset_handle, verify_keyset_handle)

def signNacl(message, sigkey):
    """
    Uses NaCl to digitally sign a message using sigkey
    
    Notes: Should only return the signature data, not the message+signature. The retured signature should be compatible with the tag parameter of the verifyNacl() method.
    Parameters:
        message (string)
        sigkey (SigningKey)
    
    Returns:
        signature (bytes)
    """

    signature = sigkey.sign(bytes(message, encoding = "utf8"))

    return signature.signature

    

def signTink(message, signing_keyset_handle):
    """
    Digitally signs message using signing key in signing_keyset_handle
    
    Notes: Only return the signature, do not return the message. The signature should be compatible with the signature_data parameter of the verifyTink() method.
    Parameters:
        message (string)
        signing_keyset_handle (KeysetHandle)
    Returns:
        signature (bytes). 
    """
    signer = signing_keyset_handle.primitive(signature.PublicKeySign)

    sigData = signer.sign(bytes(message, encoding = "utf8"))

    return sigData

def verifyNacl(message, tag, verifykey):
    """
    Verify the signature tag on a message using the verification key
    
    Parameters:
        message (string)
        tag (bytes)
        verifykey (VerifyKey)
    Returns:
        verification_status (boolean): indicating verification status (true if verified, false if something failed)
    """
    
    #forged = tag[:-1] + bytes([int(tag[-1]) ^ 1])
    try:
        verifykey.verify(bytes(message, encoding='utf8'), tag)
        return True
    except:
        return False

def verifyTink(message, signature_data, verifying_keyset_handle):
    """
    Verify the signature on a message using the verifying keyset handle

    Parameters:
        message (string)
        signature_data (bytes)
        verifying_keyset_handle (KeysetHandle)
    Returns:
        verification_status (boolean): indicating verification status (true if verified, false if something failed)
    """    
    verifier = verifying_keyset_handle.primitive(signature.PublicKeyVerify)
    
    try:
        verifier.verify(signature_data, bytes(message, encoding = "utf8"))
        return True
    except:
        return False

def computeMacNacl(message, key):
    """
    Computes a MAC using the provided key
    
    Notes: Use blake2b. Should be compatible with the verify method below. 
    Parameters:
        message (string)
        key (bytes)
    Returns:
        tag (bytes)
    """
    return blake2b(bytes(message, encoding='utf8'), key=key, encoder=nacl.encoding.HexEncoder)

def verifyMacNacl(message, tag, key):
    """
    Verifies whether the provided MAC tag is correct for the message and key
    
    Parameters:
        message (string)
        tag (bytes)
        key (bytes)
    Returns:
        verified (boolean) indicating verification status (true if verified, false if something failed)
    """
    return computeMacNacl(message, key) == tag

def computeMacTink(message, mac_keyset_handle):
    """
    Computes a MAC on the message using the provided keyset handle 
    
    Notes: The returned tag should be compatible with the verifyMacTink() method below.
    Parameters:
        message (string)
        mac_keyset_handle (KeysetHandle)
    Returns: 
        tag (bytes)
    """
    
    mac.register()

    mac_primitive = mac_keyset_handle.primitive(mac.Mac)

    tag = mac_primitive.compute_mac(bytes(message, encoding ="utf8"))

    return tag

def verifyMacTink(message, tag, mac_keyset_handle):
    """
    Verifies a mac using the provided tag and keyset handle
    
    Parameters:
        message (string)
        tag (bytes)
        mac_keyset_handle (KeysetHandle)
    Returns:
        verified (boolean) indicating verification status (true if verified, false if something failed)
    """
    mac.register()

    mac_primitive = mac_keyset_handle.primitive(mac.Mac)

    try:
        mac_primitive.verify_mac(tag, bytes(message, encoding = "utf8"))
        return True
    except:
        return False
    


if __name__ == '__main__':
    """
    print("Please implement the methods above using the appropriate cryptographic libraries. Assume library defaults if something is not specified")

    key = generateSecretKeyNacl()
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    enc = aeadEncryptNacl(key, "sup", b'some bites', nonce)
    dec = aeadDecryptNacl(enc, b'some bites', key, nonce)
    print (dec)
    print()

    keyPair = generateKeyPairNacl()
    hybenc = hybridEncryptNacl("sup2", keyPair[1])
    hybdec = hybridDecryptNacl (hybenc[0], hybenc[1], keyPair[0])
    print (hybdec)
    print()

    sigPair = generateSignatureKeypairNacl()
    tag = signNacl("sup3", sigPair[0])
    ver = verifyNacl("sup3", tag, sigPair[1])
    print (ver)


    authkey = nacl.utils.random(size=64)
    macNac = computeMacNacl("sup3", authkey)
    verifymac = verifyMacNacl("sup3", mac, authkey)
    print(verifymac)
    
    tinkey = generateSecretKeyTink()
    tinkrypt = aeadEncryptTink(tinkey, "sup5", b"supad")
    dinkrypt = aeadDecryptTink(tinkrypt, b"supad", tinkey)
    print (dinkrypt)

    tinkPair = generateHybridEncryptionKeyPairTink()
    hybTinkrypt = hybridEncryptTink("sup6", b"supad", tinkPair[1])
    hybDinkrypt = hybridDecryptTink(hybTinkrypt, b"supad", tinkPair[0])
    print (hybDinkrypt)

    sinkPair = generateSignatureKeypairTink()
    tinkSign = signTink("sup7", sinkPair[0])
    tinkVer = verifyTink("sup7", tinkSign, sinkPair[1])
    print (tinkVer)

    mac.register()
    mackeyset = tink.new_keyset_handle(mac.mac_key_templates.HMAC_SHA256_128BITTAG)
    macTink = computeMacTink("sup8", mackeyset)
    verMacTink = verifyMacTink("sup8", macTink, mackeyset)
    print (verMacTink)
    #t
    """
