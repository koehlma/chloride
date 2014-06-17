# -*- coding:utf-8 -*-
#
# Copyright (C) 2014, Maximilian Köhl <linuxmaxi@googlemail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import base64
import binascii
import collections
import ctypes
import ctypes.util

__version__ = '0.0.1'
__project__ = 'Chloride'
__short_name__ = 'chloride'
__author__ = 'Maximilian Köhl'
__email__ = 'linuxmaxi@googlemail.com'
__website__ = 'http://www.github.com/socialcube/chloride'
__download_url__ = 'https://github.com/socialcube/chloride/tarball/master'
__source__ = 'https://github.com/socialcube/chloride/'
__vcs__ = 'git://github.com/socialcube/chloride.git'
__copyright__ = 'Copyright (C) 2014, Maximilian Köhl'
__desc_short__ = 'an object oriented pure python libsodium wrapper'
__desc_long__ = 'an object oriented pure python libsodium wrapper'

_library = ctypes.util.find_library('sodium')

if _library:
    _lib = ctypes.CDLL(_library)
    
    _lib.sodium_init()
    _lib.sodium_version_string.restype = ctypes.c_char_p

    version_string = _lib.sodium_version_string().decode('ascii')
    version_major = _lib.sodium_library_version_major()
    version_minor = _lib.sodium_library_version_minor()
else:
    import os
    if os.environ.get('CHLORIDE_LIBSODIUM_WARN', None) == 'true':
        import warnings
        warnings.warn('unable to find libsodium')
              
        version_string = '0.5.0'
        version_major = 5
        version_minor = 0
    else:
        raise OSError('unable to find libsodium')

_Version = collections.namedtuple('Version', ['string', 'major', 'minor'])

version = _Version(version_string, version_major, version_minor) 

def randombytes(size):
    buffer = ctypes.create_string_buffer(size)
    _lib.randombytes(buffer, size)
    return buffer.raw 

class EncodeableBytesMixin():
    @classmethod
    def from_hex(cls, key):
        return cls(binascii.unhexlify(key.encode('ascii')))
    
    @classmethod
    def from_base32(cls, key):
        return cls(base64.b32decode(key.encode('ascii')))
        
    @classmethod
    def from_base64(cls, key):
        return cls(base64.b64decode(key.encode('ascii')))
    
    @property
    def hex(self):
        return binascii.hexlify(self).decode('ascii')
    
    @property
    def base32(self):
        return base64.b32encode(self).decode('ascii')
    
    @property
    def base64(self):
        return base64.b64encode(self).decode('ascii')

class HashableBytesMixin():
    @property
    def sha256(self):
        return hash_sha256(self)
    
    @property
    def sha512(self):
        return hash_sha512(self)
    
class Key(bytes, EncodeableBytesMixin, HashableBytesMixin): pass

class Seed(bytes, EncodeableBytesMixin, HashableBytesMixin): pass

class Digest(bytes, EncodeableBytesMixin, HashableBytesMixin): pass

if _library:
    _lib.crypto_box_primitive.restype = ctypes.c_char_p
    
    _box_publickeybytes = _lib.crypto_box_publickeybytes()
    _box_secretkeybytes = _lib.crypto_box_secretkeybytes()
    _box_noncebytes = _lib.crypto_box_noncebytes()
    _box_primitive = _lib.crypto_box_primitive().decode()
    _box_beforenmbytes = _lib.crypto_box_beforenmbytes()
    _box_zerobytes = _lib.crypto_box_zerobytes()
    _box_boxzerobytes = _lib.crypto_box_boxzerobytes()
    
    _scalarmult_base = _lib.crypto_scalarmult_base
    _box_keypair = _lib.crypto_box_keypair
    _box_beforenm = _lib.crypto_box_beforenm
    _box_afternm = _lib.crypto_box_afternm
    _box_open_afternm = _lib.crypto_box_open_afternm
else:
    _box_publickeybytes = 32
    _box_secretkeybytes = 32
    _box_noncebytes = 24
    _box_primitive = 'curve25519xsalsa20poly1305'
    _box_beforenmbytes = 32
    _box_zerobytes = 32
    _box_boxzerobytes = 16    

class Box():
    PUBLIC_KEY_SIZE = _box_publickeybytes
    SECRET_KEY_SIZE = _box_secretkeybytes
    NONCE_SIZE = _box_noncebytes
    PRIMITIVE = _box_primitive
    
    _SHARED_KEY_SIZE = _box_beforenmbytes
    _ZERO_SIZE = _box_zerobytes
    _BOX_ZERO_SIZE = _box_boxzerobytes
    
    class Message(bytes):
        @property
        def nonce(self):
            return self[:Box.NONCE_SIZE]
        
        @property
        def ciphertext(self):
            return self[Box.NONCE_SIZE:]
    
    @staticmethod
    def generate_public_key(secret_key):
        public_key = ctypes.create_string_buffer(Box.PUBLIC_KEY_SIZE)
        assert not _scalarmult_base(public_key, secret_key)
        return Key(public_key.raw)
    
    @staticmethod
    def generate_keypair():
        public_key = ctypes.create_string_buffer(Box.PUBLIC_KEY_SIZE)
        secret_key = ctypes.create_string_buffer(Box.SECRET_KEY_SIZE)
        assert not _box_keypair(public_key, secret_key)
        return Key(public_key.raw), Key(secret_key.raw)
    
    @staticmethod
    def generate_nonce():
        return randombytes(Box.NONCE_SIZE)
    
    def __init__(self, public_key, secret_key):
        if isinstance(public_key, Key):
            self._public_key = public_key
        else:
            self._public_key = Key(public_key)
        if isinstance(secret_key, Key):
            self._secret_key = secret_key
        else:
            self._secret_key = Key(secret_key)
        assert len(self._public_key) == Box.PUBLIC_KEY_SIZE
        assert len(self._secret_key) == Box.SECRET_KEY_SIZE
        shared_key = ctypes.create_string_buffer(self._SHARED_KEY_SIZE)
        assert not _box_beforenm(shared_key, public_key, secret_key)
        self._shared_key = shared_key.raw
        
    @property
    def public_key(self):
        return self._public_key
    
    @property
    def secret_key(self):
        return self._secret_key
     
    def encrypt(self, message, nonce=None):
        nonce = nonce or randombytes(Box.NONCE_SIZE)
        assert len(nonce) == Box.NONCE_SIZE
        plaintext = b'\x00' * Box._ZERO_SIZE + message
        length = len(plaintext)
        ciphertext = ctypes.create_string_buffer(length)
        assert not _box_afternm(ciphertext, plaintext, length, nonce,
                                self._shared_key)
        return nonce + ciphertext.raw[Box._BOX_ZERO_SIZE:]

    def decrypt(self, message, nonce=None):
        if nonce:
            ciphertext = message
        else:
            nonce = message[:Box.NONCE_SIZE]
            ciphertext = message[Box.NONCE_SIZE:]
        assert len(nonce) == Box.NONCE_SIZE
        ciphertext = b'\x00' * Box._BOX_ZERO_SIZE + ciphertext
        length = len(ciphertext)
        plaintext = ctypes.create_string_buffer(length)
        assert not _box_open_afternm(plaintext, ciphertext, length, nonce,
                                     self._shared_key)
        return plaintext.raw[Box._ZERO_SIZE:]

if _library:
    _lib.crypto_secretbox_primitive.restype = ctypes.c_char_p

    _secretbox_keybytes = _lib.crypto_secretbox_keybytes()
    _secretbox_noncebytes = _lib.crypto_secretbox_noncebytes()
    _secretbox_primitive = _lib.crypto_secretbox_primitive().decode()
    _secretbox_zerobytes = _lib.crypto_secretbox_zerobytes()
    _secretbox_boxzerobytes = _lib.crypto_secretbox_boxzerobytes()

    _secretbox = _lib.crypto_secretbox
    _secretbox_open = _lib.crypto_secretbox_open
else:
    _secretbox_keybytes = 32
    _secretbox_noncebytes = 24
    _secretbox_primitive = 'xsalsa20poly1305'
    _secretbox_zerobytes = 32
    _secretbox_boxzerobytes = 16

class SecretBox():    
    KEY_SIZE = _secretbox_keybytes
    NONCE_SIZE = _secretbox_noncebytes
    PRIMITIVE = _secretbox_primitive
    
    _ZERO_SIZE = _secretbox_zerobytes
    _ZERO_BOX_SIZE = _secretbox_boxzerobytes
    
    @staticmethod
    def generate_key():
        return Key(randombytes(SecretBox.KEY_SIZE))
    
    @classmethod
    def generate(cls):
        return cls(SecretBox.generate_key())
    
    def __init__(self, key):
        assert len(key) == SecretBox.KEY_SIZE
        if isinstance(key, Key):
            self._key = key
        else:
            self._key = Key(key)

    @property
    def key(self):
        return self._key
    
    def encrypt(self, message, nonce=None):
        nonce = nonce or randombytes(SecretBox.NONCE_SIZE)
        assert len(nonce) == SecretBox.NONCE_SIZE
        plaintext = b'\x00' * SecretBox._ZERO_SIZE + message
        length = len(plaintext)
        ciphertext = ctypes.create_string_buffer(length)
        assert not _secretbox(ciphertext, plaintext, length, nonce, self._key)
        return nonce + ciphertext.raw[SecretBox._ZERO_BOX_SIZE:]
        
    def decrypt(self, message, nonce=None):
        if nonce:
            ciphertext = message
        else:
            nonce = message[:SecretBox.NONCE_SIZE]
            ciphertext = message[SecretBox.NONCE_SIZE:]
        assert len(nonce) == SecretBox.NONCE_SIZE
        ciphertext = b'\x00' * SecretBox._ZERO_BOX_SIZE + ciphertext
        length = len(ciphertext)
        plaintext = ctypes.create_string_buffer(length)
        assert not _secretbox_open(plaintext, ciphertext, length, nonce,
                                   self._key)
        return plaintext[SecretBox._ZERO_SIZE:]

if _library:
    _lib.crypto_sign_primitive.restype = ctypes.c_char_p

    _sign_bytes = _lib.crypto_sign_bytes()
    _sign_publickeybytes = _lib.crypto_sign_publickeybytes()
    _sign_secretkeybytes = _lib.crypto_sign_secretkeybytes()
    _sign_primitive = _lib.crypto_sign_primitive().decode()
    _sign_seedbytes = _lib.crypto_sign_seedbytes()
    
    _sign_seed_keypair = _lib.crypto_sign_seed_keypair
    _sign_keypair = _lib.crypto_sign_keypair
    _sign = _lib.crypto_sign
    _sign_open = _lib.crypto_sign_open
else:
    _sign_bytes = 64
    _sign_publickeybytes = 32
    _sign_secretkeybytes = 64
    _sign_primitive = 'ed25519'
    _sign_seedbytes = 32

class Sign():    
    SIGNATURE_SIZE = _sign_bytes
    
    VERIFY_KEY_SIZE = _sign_publickeybytes
    SIGN_KEY_SIZE = _sign_secretkeybytes
    PRIMITIVE = _sign_primitive
    
    SEED_SIZE = _sign_seedbytes
    
    class Message(bytes):
        @property
        def signature(self):
            return self[:Signing.SIGNATURE_SIZE]
        
        @property
        def message(self):
            return self[Signing.SIGNATURE_SIZE:]
        
    @staticmethod
    def generate_seed():
        return Seed(randombytes(Signing.SEED_SIZE))
    
    @staticmethod
    def generate_keypair(seed=None):
        verify_key = ctypes.create_string_buffer(Sign.VERIFY_KEY_SIZE)
        sign_key = ctypes.create_string_buffer(Sign.SIGN_KEY_SIZE)        
        if seed:
            assert len(seed) == Sign.SEED_SIZE
            assert not _sign_seed_keypair(verify_key, sign_key, seed)
        else:
            assert not _sign_keypair(verify_key, sign_key)
        return Key(verify_key), Key(sign_key)
    
    @classmethod
    def generate(cls, seed=None):
        verify_key, sign_key = Sign.generate_keypair(seed)
        return cls(verify_key, sign_key, seed)
    
    def __init__(self, verify_key, sign_key=None, seed=None):
        if isinstance(verify_key, Key):
            self._verify_key = verify_key
        else:
            self._verify_key = Key(verify_key)
        if  sign_key is None:
            self._sign_key = None
        elif isinstance(sign_key, Key):
            self._sign_key = sign_key
        else:
            self._sign_key = Key(sign_key)
        if seed is None:
            self._seed = None
        elif isinstance(seed, Seed):
            self._seed = seed
        else:
            self._seed = Seed(seed)

    @property
    def verify_key(self):
        return self._verify_key
    
    @property
    def sign_key(self):
        return self._sign_key
    
    @property
    def seed(self):
        return self._seed
    
    def sign(self, message):
        assert self._sign_key is not None
        length = len(message)
        signature = ctypes.create_string_buffer(length + Sign.SIGNATURE_SIZE)
        assert not _sign(signature, ctypes.pointer(ctypes.c_ulonglong()),
                         message, length, self._sign_key)
        return Sign.Message(signature.raw)
        
    def verify(self, message, signature=None):
        if signature:
            signed_message = signature + message
        else:
            signed_message = message
        length = len(signed_message)
        message = ctypes.create_string_buffer(length)
        message_length = ctypes.pointer(ctypes.c_ulonglong())
        assert not _sign_open(message, message_length, signed_message, length,
                              self._verify_key)
        return signed_message[Sign.SIGNATURE_SIZE:]

if _library:
    _lib.crypto_auth_primitive.restype = ctypes.c_char_p

    _auth_bytes = _lib.crypto_auth_bytes()
    _auth_keybytes = _lib.crypto_auth_keybytes()
    _auth_primitive = _lib.crypto_auth_primitive().decode()

    _auth = _lib.crypto_auth
    _auth_verify = _lib.crypto_auth_verify
else:
    _auth_bytes = 32
    _auth_keybytes = 32
    _auth_primitive = 'hmacsha512256'

class Auth():
    TOKEN_SIZE = _auth_bytes
    KEY_SIZE = _auth_keybytes
    PRIMITIVE = _auth_primitive
    
    class Message(bytes):
        @property
        def token(self):
            return self[:Auth.TOKEN_SIZE]
        
        @property
        def message(self):
            return self[Auth.TOKEN_SIZE:]
    
    @staticmethod
    def generate_key():
        return Key(randombytes(Auth.KEY_SIZE))
    
    @classmethod
    def generate(cls):
        return cls(Auth.generate_key())
    
    def __init__(self, key):
        assert len(key) == Auth.KEY_SIZE
        if isinstance(key, Key):
            self._key = key
        else:
            self._key = Key(key)
    
    def auth(self, message):
        length = len(message)
        token = ctypes.create_string_buffer(Auth.TOKEN_SIZE)
        assert not _auth(token, message, length, self._key)
        return Auth.Message(token.raw + message)
    
    def verify(self, message, token=None):
        if not token:
             token = message[:Auth.TOKEN_SIZE]
             message = message[Auth.TOKEN_SIZE:]
        length = len(message)
        assert not _auth_verify(token, message, length, self._key)
        return message   

if _library:
    _sha256_bytes = _lib.crypto_hash_sha256_bytes()

    _sha256_init = _lib.crypto_hash_sha256_init
    _sha256_update = _lib.crypto_hash_sha256_update
    _sha256_final = _lib.crypto_hash_sha256_final
else:
    _sha256_bytes = 32

class SHA256():
    PRIMITIVE = 'sha256'
    SIZE = _sha256_bytes
    
    class State(ctypes.Structure):
        _fields_ = [('state', ctypes.c_uint32 * 8),
                    ('count', ctypes.c_uint32 * 2),
                    ('buffer', ctypes.c_char * 64)]  

    State.SIZE = ctypes.sizeof(State)
    
    def __init__(self, inital=None):
        self._state = SHA256.State()
        self._pointer = ctypes.pointer(self._state)
        _sha256_init(self._pointer)
        if inital: self.update(inital)
    
    def __bytes__(self):
        return self.digest
    
    def update(self, chunk):
        _sha256_update(self._pointer, chunk, len(chunk))
    
    @property
    def digest(self):
        state = SHA256.State()
        pointer = ctypes.pointer(state)
        ctypes.memmove(pointer, self._pointer, SHA256.State.SIZE)
        digest = ctypes.create_string_buffer(SHA256.SIZE)
        _sha256_final(pointer, digest)
        return Digest(digest.raw)
if _library:
    _sha512_bytes = _lib.crypto_hash_sha512_bytes()
    
    _sha512_init = _lib.crypto_hash_sha512_init
    _sha512_update = _lib.crypto_hash_sha512_update
    _sha512_final = _lib.crypto_hash_sha512_final
else:
    _sha512_bytes = 64

class SHA512():
    PRIMITIVE = 'sha512'
    SIZE = _sha512_bytes
    
    class State(ctypes.Structure):
        _fields_ = [('state', ctypes.c_uint64 * 8),
                    ('count', ctypes.c_uint64 * 2),
                    ('buffer', ctypes.c_char * 128)]  

    State.SIZE = ctypes.sizeof(State)
    
    def __init__(self, inital=None):
        self._state = SHA512.State()
        self._pointer = ctypes.pointer(self._state)
        _sha512_init(self._pointer)
        if inital: self.update(inital)
    
    def __bytes__(self):
        return self.digest
    
    def update(self, chunk):
        _sha512_update(self._pointer, chunk, len(chunk))
    
    @property
    def digest(self):
        state = SHA512.State()
        pointer = ctypes.pointer(state)
        ctypes.memmove(pointer, self._pointer, SHA512.State.SIZE)
        digest = ctypes.create_string_buffer(SHA512.SIZE)
        _sha512_final(pointer, digest)
        return Digest(digest.raw)

Hash = SHA512

if _library:
    _blake2b_bytes_min = _lib.crypto_generichash_blake2b_bytes_min()
    _blake2b_bytes_max = _lib.crypto_generichash_blake2b_bytes_max()
    _blake2b_bytes = _lib.crypto_generichash_blake2b_bytes()
    _blake2b_keybytes_min = _lib.crypto_generichash_blake2b_keybytes_min()
    _blake2b_keybytes_max = _lib.crypto_generichash_blake2b_keybytes_max()
    _blake2b_keybytes = _lib.crypto_generichash_blake2b_keybytes()
    _blake2b_saltbytes = _lib.crypto_generichash_blake2b_saltbytes()
    _blake2b_personalbytes = _lib.crypto_generichash_blake2b_personalbytes()
    
    _blake2b_init_sp = _lib.crypto_generichash_blake2b_init_salt_personal
    _blake2b_init = _lib.crypto_generichash_blake2b_init
    _blake2b_update = _lib.crypto_generichash_blake2b_update
    _blake2b_final = _lib.crypto_generichash_blake2b_final
else:
    _blake2b_bytes_min = 16
    _blake2b_bytes_max = 64
    _blake2b_bytes = 32
    _blake2b_keybytes_min = 16
    _blake2b_keybytes_max = 64
    _blake2b_keybytes = 32
    _blake2b_saltbytes = 16
    _blake2b_personalbytes = 16

class BLAKE2B():
    PRIMITVE = 'blake2b'
    MIN_SIZE = _blake2b_bytes_min
    MAX_SIZE = _blake2b_bytes_max
    DEFAULT_SIZE = _blake2b_bytes
    SIZE = range(MIN_SIZE, MAX_SIZE + 1)
    MIN_KEY_SIZE = _blake2b_keybytes_min
    MAX_KEY_SIZE = _blake2b_keybytes_max
    DEFAULT_KEY_SIZE = _blake2b_keybytes
    KEY_SIZE = range(MIN_KEY_SIZE, MAX_KEY_SIZE + 1)
    SALT_SIZE = _blake2b_saltbytes
    PERSONAL_SIZE = _blake2b_personalbytes
    
    class State(ctypes.Structure):
        _fields_ = [('h', ctypes.c_uint64 * 8),
                    ('t', ctypes.c_uint64 * 2),
                    ('f', ctypes.c_uint64 * 2),
                    ('buffer', ctypes.c_char * 256),
                    ('buflen', ctypes.c_size_t),
                    ('last_node', ctypes.c_uint8)]  

    State.SIZE = ctypes.sizeof(State)
    
    @staticmethod
    def generate_key(size=DEFAULT_KEY_SIZE):
        assert size in BLAKE2B.KEY_SIZE
        return Key(randombytes(size))
    
    @staticmethod
    def generate_salt():
        return randombytes(BLAKE2B.SALT_SIZE)
    
    @staticmethod
    def generate_personal():
        return randombytes(BLAKE2B.PERSONAL_SIZE)
    
    def __init__(self, inital=None, size=DEFAULT_SIZE, key=None, salt=None,
                 personal=None):
        self._state = BLAKE2B.State()
        self._pointer = ctypes.pointer(self._state)
        assert size in BLAKE2B.SIZE
        self._size = size
        if key:
            self._key_length = len(key)
            assert self._key_length in BLAKE2B.KEY_SIZE
        else:
            self._key_length = 0
        self._key = key
        self._salt = salt
        self._personal = personal
        if salt and personal:
            assert len(salt) == BLAKE2B.SALT_SIZE
            assert len(personal) == BLAKE2B.PERSONAL_SIZE
            _blake2b_init_sp(self._pointer, self._key, self._key_length,
                             self._size, self._salt, self._personal)
        else:
            _blake2b_init(self._pointer, self._key, self._key_length,
                          self._size) 
        if inital:
            self.update(inital)
    
    def __bytes__(self):
        return self.digest
    
    def update(self, chunk):
        _blake2b_update(self._pointer, chunk, len(chunk))
    
    @property
    def digest(self):
        state = BLAKE2B.State()
        pointer = ctypes.pointer(state)
        ctypes.memmove(pointer, self._pointer,BLAKE2B.State.SIZE)
        digest = ctypes.create_string_buffer(self._size)
        _blake2b_final(pointer, digest, self._size)
        return Digest(digest.raw)
    
Generichash = BLAKE2B

if _library:
    _sha256 = _lib.crypto_hash_sha256
    _sha512 = _lib.crypto_hash_sha512
    _blake2b_sp = _lib.crypto_generichash_blake2b_salt_personal
    _blake2b = _lib.crypto_generichash_blake2b

def hash_sha256(buffer):
    digest = ctypes.create_string_buffer(SHA256.SIZE)
    _sha256(digest, buffer, len(buffer))
    return Digest(digest.raw)

def hash_sha512(buffer):
    digest = ctypes.create_string_buffer(SHA512.SIZE)
    _sha512(digest, buffer, len(buffer))
    return Digest(digest.raw)

def hash_blake2b(buffer, size=BLAKE2B.DEFAULT_SIZE, key=None, salt=None,
                personal=None):
    assert size in BLAKE2B.SIZE
    digest = ctypes.create_string_buffer(size)
    if key:
        key_length = len(key)
        assert key_length in BLAKE2B.KEY_SIZE
    else:
        key_length = 0    
    if salt and personal:
        assert len(salt) == BLAKE2B.SALT_SIZE
        assert len(personal) == BLAKE2B.PERSONAL_SIZE
        _blake2b_sp(digest, size, buffer, len(buffer), key, key_length, salt,
                    personal)
    else:
        _blake2b(digest, size, buffer, len(buffer), key, key_length) 
    return Digest(digest.raw)

__all__ = ['Box', 'SecretBox', 'Sign', 'Auth', 'SHA256', 'SHA512', 'Hash',
           'BLAKE2B', 'Generichash', 'hash_sha256', 'hash_sha512',
           'hash_blake2b']

if __name__ == '__main__':
    # Public Key Cryptography
    pbob, sbob = Box.generate_keypair()
    palice, salice = Box.generate_keypair()
    
    bob = Box(palice, sbob)
    alice = Box(pbob, salice)

    message = bob.encrypt(b'Hello Alice!')
    print(alice.decrypt(message))

    message = alice.encrypt(b'Hello Bob!')
    print(bob.decrypt(message))

    
    # Secret Key Cryptography
    secret = SecretBox.generate_key()

    bob = SecretBox(secret)
    alice = SecretBox(secret)

    message = bob.encrypt(b'Hello Alice!')
    print(alice.decrypt(message))

    message = alice.encrypt(b'Hello Bob!')
    print(bob.decrypt(message))
    
    
    # Digital Signatures
    vbob, sbob = Sign.generate_keypair()
    valice, salice = Sign.generate_keypair()
        
    bob = Sign(vbob, sbob)
    alice = Sign(valice, salice)
    
    alice_bob = Sign(vbob)
    bob_alice = Sign(valice)
    
    print(vbob)
    print(valice)
    
    message = bob.sign(b'Hello Alice!')
    print(alice_bob.verify(message))
    
    message = alice.sign(b'Hello Bob!')
    print(bob_alice.verify(message))
    
    
    # HMAC based Authentication
    secret = Auth.generate_key()
          
    bob = Auth(secret)
    alice = Auth(secret)
    
    message = bob.auth(b'Hello Alice!')
    print(alice.verify(message))
    
    message = alice.auth(b'Hello Bob!')
    print(bob.verify(message))
    
    
    # Hashing
    import hashlib
    
    msg = b'Hello World!'
    
    sha256 = SHA256()
    sha256.update(msg)
    
    print(sha256.digest)   
    print(hashlib.sha256(msg).hexdigest())
    
    sha512 = SHA512()
    sha512.update(msg)
     
    print(sha512.digest)
    print(hashlib.sha512(msg).hexdigest())
    
    print(hash_blake2b(msg))
    
    generichash = Generichash(msg)
    print(generichash.digest)
    
