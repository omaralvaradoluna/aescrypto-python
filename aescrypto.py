#!/usr/bin/python
# -*- coding: UTF-8 -*-

import base64
import numpy as np
from math import floor, ceil
from time import time
from datetime import datetime as dt

class Aes:
    def __init__(self):
        return

    # sBox is pre-computed multiplicative inverse in GF[2^8] used in subBytes and keyExpansion [§5.1.1]
    sBox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82,
            0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
            0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96,
            0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
            0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
            0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
            0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
            0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32,
            0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
            0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
            0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
            0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
            0xb0, 0x54, 0xbb, 0x16]

    # rCon is Round Constant used for the Key Expansion [1st col is 2^[r-1] in GF[2^8]] [§5.2]
    rCon = [[0x00, 0x00, 0x00, 0x00], [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00], [0x04, 0x00, 0x00, 0x00],
            [0x08, 0x00, 0x00, 0x00], [0x10, 0x00, 0x00, 0x00], [0x20, 0x00, 0x00, 0x00], [0x40, 0x00, 0x00, 0x00],
            [0x80, 0x00, 0x00, 0x00], [0x1b, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]]
    """
          AES Cipher function [§5.1]: encrypt 'input' with Rijndael algorithm
          @param input message as byte-array (16 bytes)
          @param w     key schedule as 2D byte-array (Nr+1 x Nb bytes) -
                       generated from the cipher key by keyExpansion()
          @return      ciphertext as byte-array (16 bytes)
    """

    def cipher(self, inputx, w):

        Nb = 4  # block size (in words): no of columns in state (fixed at 4 for AES)
        Nr = len(w) / Nb - 1  # no of rounds: 10/12/14 for 128/192/256-bit keys
        state = [[0 for _ in range(Nb)] for _ in range(4)]  # initialise 4xNb byte-array 'state' with input [§3.4]
        for i in range(0, 4 * Nb):
            state[i % 4][int(floor(i / 4))] = inputx[i]
        state = self.addRoundKey(state, w, 0, Nb)

        for roundx in range(1, Nr):  # apply Nr rounds
            state = self.subBytes(state, Nb)
            state = self.shiftRows(state, Nb)
            state = self.mixColumns(state, Nb)
            state = self.addRoundKey(state, w, roundx, Nb)

        state = self.subBytes(state, Nb)
        state = self.shiftRows(state, Nb)
        state = self.addRoundKey(state, w, Nr, Nb)

        output = [0 for _ in range(4 * Nb)]  # convert state to 1-d array before returning [§3.4]
        for i in range(0, 4 * Nb):
            output[i] = state[i % 4][int(floor(i / 4))]
        return output

    """
      Xor Round Key into state S [§5.1.4].
      @param string $state
      @param string $w
      @param string $rnd
      @param string $Nb
   """

    def addRoundKey(self, state, w, rnd, Nb):
        for r in range(0, 4):
            for c in range(0, Nb):
                state[r][c] ^= w[rnd * 4 + c][r]
        return state

    """
     Apply SBox to state S [§5.1.1].
      @param  string $s
      @param  string $Nb
      @return string
    """

    def subBytes(self, s, Nb):
        for r in range(0, 4):
            for c in range(0, Nb):
                s[r][c] = self.sBox[s[r][c]]
        return s

    """
      Shift row r of state S left by r bytes [§5.1.2].
      @param  string $s
      @param  string $Nb
      @return string
    """

    def shiftRows(self, s, Nb):
        t = [0 for _ in range(4)]
        for r in range(1, 4):
            for c in range(0, 4):
                t[c] = s[r][(c + r) % Nb]  # shift into temp copy
            for c in range(0, 4):
                s[r][c] = t[c]  # and copy back
        # note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):
        return s  # see fp.gladman.plus.com/cryptography_technology/rijndael/aes.spec.311.pdf

    """
          Combine bytes of each col of state S [§5.1.3].
          @param  string $s
          @param  string $Nb
          @return string
    """

    def mixColumns(self, s, Nb):
        for c in range(0, 4):
            a = [0 for _ in range(4)]  # 'a' is a copy of the current column from 's'
            b = [0 for _ in range(4)]  # 'b' is a•{02} in GF(2^8)
            for i in range(0, 4):
                a[i] = s[i][c]
                if (s[i][c] & 0x80):
                    b[i] = s[i][c] << 1 ^ 0x011b
                else:
                    b[i] = s[i][c] << 1
            # a[n] ^ b[n] is a•{03} in GF(2^8)
            s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]  # 2*a0 + 3*a1 + a2 + a3
            s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]  # a0 * 2*a1 + 3*a2 + a3
            s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]  # a0 + a1 + 2*a2 + 3*a3
            s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]  # 3*a0 + a1 + a2 + 2*a3
        return s

    """
        Generate Key Schedule from Cipher Key [§5.2].
        Perform key expansion on cipher key to generate a key schedule.
        @param  key cipher key byte-array (16 bytes).
        @return key schedule as 2D byte-array (Nr+1 x Nb bytes).
    """

    def keyExpansion(self, key):
        Nb = 4  # block size (in words): no of columns in state (fixed at 4 for AES)
        Nk = len(key) / 4  # key length (in words): 4/6/8 for 128/192/256-bit keys
        Nr = Nk + 6  # no of rounds: 10/12/14 for 128/192/256-bit keys

        # w = [[0 for _ in range(4)] for _ in range(Nb * (Nr + 1))]
        w = []
        # temp = [0 for _ in range(4)]

        for i in range(0, Nk):
            r = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]
            w.append(r)

        for i in range(Nk, Nb * (Nr + 1)):
            # w[i] = [0 for _ in range(4)]
            temp = []
            for t in range(0, 4):
                temp.append(w[i - 1][t])

            if (i % Nk) == 0:
                temp = self.subWord(self.rotWord(temp))
                for t in range(0, 4):
                    temp[t] ^= self.rCon[i / Nk][t]
            elif (Nk > 6) and ((i % Nk) == 4):
                temp = self.subWord(temp)

            w.append([])
            for t in range(0, 4):
                t2 = w[i - Nk][t] ^ temp[t]

                w[i].append(t2)
        return w

    """
      Apply SBox to 4-byte word w.
      @param  string $w
      @return string
    """

    def subWord(self, w):
        for i in range(0, 4):
            w[i] = self.sBox[w[i]]
        return w

    """
      Rotate 4-byte word w left by one byte.
      @param  string $w
      @return string
    """

    @staticmethod
    def rotWord(w):
        tmp = w[0]
        for i in range(0, 3):
            w[i] = w[i + 1]
        w[3] = tmp
        return w


class AesCtr(Aes):
    def __init__(self):
        return

    def encrypt(self, plaintext, password, nBits):
        blockSize = 16  # block size fixed at 16 bytes / 128 bits (Nb=4) for AES
        if not ((nBits == 128) or (nBits == 192) or (nBits == 256)):
            return ''  # standard allows 128/192/256 bit keys
        # note PHP (5) gives us plaintext and password in UTF8 encoding!
        # use AES itself to encrypt password to get cipher key (using plain password as source for
        # key expansion) - gives us well encrypted key

        nBytes = nBits / 8  # no bytes in key
        pwBytes = []

        for i in range(0, int(nBytes)):
            if i >= len(password):
                pwBytes.append(0)
            else:
                pwBytes.append(ord(password[i]) & 0xff)

        oAES = Aes()
        expanded = oAES.keyExpansion(pwBytes)
        key = oAES.cipher(pwBytes, expanded)
        key = key + key[:nBytes - 16]  # expand key to 16/24/32 bytes long

        # initialise 1st 8 bytes of counter block with nonce (NIST SP800-38A §B.2): [0-1] = millisec,
        # [2-3] = random, [4-7] = seconds, giving guaranteed sub-ms uniqueness up to Feb 2106
        counterBlock = [0 for _ in range(16)]
        nonce = int(floor((dt.now()-dt(1970,1,1)).total_seconds() * 1000))  # timestamp: milliseconds since 1-Jan-1970
        nonceMs = nonce % 1000
        nonceSec = int(floor(nonce / 1000))
        rs = np.random.RandomState(10)
        nonceRnd = int(floor(rs.uniform(0, 0xffff)))

        for i in range(0, 2):
            counterBlock[i] = self.urs(nonceMs, i * 8) & 0xff
        for i in range(0, 2):
            counterBlock[i + 2] = self.urs(nonceRnd, i * 8) & 0xff
        for i in range(0, 4):
            counterBlock[i + 4] = self.urs(nonceSec, i * 8) & 0xff

        # and convert it to a string to go on the front of the ciphertext
        ctrTxt = ""
        for i in range(0, 8):
            ctrTxt += chr(counterBlock[i])

        # generate key schedule - an expansion of the key into distinct Key Rounds for each round
        oAES = Aes()
        keySchedule = oAES.keyExpansion(key)
        blockCount = int(ceil(len(plaintext) / float(blockSize)))
        ciphertxt = ['' for _ in range(blockCount)]  # ciphertext as array of strings

        for b in range(0, blockCount):
            # set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
            # done in two stages for 32-bit ops: using two words allows us to go past 2^32 blocks (68GB)
            for c in range(0, 4):
                counterBlock[15 - c] = self.urs(b, c * 8) & 0xff
            for c in range(0, 4):
                counterBlock[15 - c - 4] = self.urs((b + 1) / 0x100000000, c * 8)
            oAES = Aes()
            cipherCntr = oAES.cipher(counterBlock, keySchedule)  # -- encrypt counter block --
            # block size is reduced on final block
            if b < (blockCount - 1):
                blockLength = blockSize
            else:
                blockLength = ((len(plaintext) - 1) % blockSize + 1)
            cipherByte = [0 for x in range (blockLength)]
            for i in range(0, blockLength):  # -- xor plaintext with ciphered counter byte-by-byte --
                cipherByte[i] = cipherCntr[i] ^ ord(plaintext[b * blockSize + i])
                cipherByte[i] = chr(cipherByte[i])
            ciphertxt[b] = "".join(cipherByte)  # escape troublesome characters in ciphertext
        ciphertext = ctrTxt + ''.join(ciphertxt)
        ciphertext = base64.encodestring(ciphertext)
        return ciphertext

    def decrypt(self,ciphertext,password,nBits):
        blockSize = 16; # block size fixed at 16 bytes / 128 bits (Nb=4) for AES
        if not ((nBits == 128) or (nBits == 192) or (nBits == 256)):
            return '' # standard allows 128/192/256 bit keys
        ciphertext = base64.decodestring(ciphertext)
        # use AES to encrypt password (mirroring encrypt routine)
        nBytes = nBits / 8; # no bytes in key
        pwBytes = []
        for i in range(0,nBytes):
            if i >= len(password):
                pwBytes.append(0)
            else:
                pwBytes.append(ord(password[i]) & 0xff)

        oAES = Aes()
        key = oAES.cipher(pwBytes,oAES.keyExpansion(pwBytes))
        key = key+key[:nBytes-16]

        counterBlock = [0 for _ in range(16)]
        ctrTxt = ciphertext[:8]
        for i in range(0,8):
            counterBlock[i] = ord(ctrTxt[i])
        keySchedule = oAES.keyExpansion(key)
        nBlocks = int(ceil((len(ciphertext)-8)/float(blockSize)))
        ct = [0 for _ in range(0,nBlocks)]
        for b in range(0,nBlocks):
            ct[b] = ciphertext[8+b*blockSize:8+b*blockSize+16]
        ciphertext = ct
        plaintxt = [0 for _ in range(nBlocks)]

        for b in range(0,nBlocks):
            for c in range (0,4):
                counterBlock[15-c] = self.urs(b , c*8) & 0xff
            for c in range (0,4):
                counterBlock[15-c-4] = self.urs((b + 1.0) / 0x100000000 - 1.0, c * 8) & 0xff
            cipherCntr = oAES.cipher(counterBlock, keySchedule)
            plaintxtByte = [0 for _ in range(len(ciphertext[b]))]
            for i in range(0, len(ciphertext[b])):
                plaintxtByte[i] = cipherCntr[i] ^ ord(ciphertext[b][i])
                plaintxtByte[i] = chr(plaintxtByte[i])
            plaintxt[b] = ''.join(plaintxtByte)
        plaintext = ''.join(plaintxt)
        return plaintext



    def urs(self, a, b):
        a = int(floor(abs(a))) & 0xffffffff
        # a &= 0xffffffff
        b &= 0x1f  # (bounds check)
        if (a & 0x80000000) and (b > 0):  # if left-most bit set
            a = (a >> 1) & 0x7fffffff  # right-shift one bit & clear left-most bit
            a = a >> (b - 1)  # remaining right-shifts
        else:  # otherwise
            a = (a >> b)  # use normal right-shift
        return a
