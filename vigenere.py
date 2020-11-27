#!/usr/bin/env python
import string
import math
from itertools import product


ciphertext = "SXULW GNXIO WRZJG OFLCM RHEFZ ALGSP DXBLM PWIQT XJGLA RIYRI BLPPC HMXMG CTZDL CLKRU YMYSJ TWUTX ZCMRH EFZAL OTMNL BLULV MCQMG CTZDL CPTBI AVPML NVRJN SSXWT XJGLA RIQPE FUGVP PGRLG OMDKW RSIFK TZYRM QHNXD UOWQT XJGLA RIQAV VTZVP LMAIV ZPHCX FPAVT MLBSD OIFVT PBACS EQKOL BCRSM AMULP SPPYF CXOKH LZXUO GNLID ZVRAL DOACC INREN YMLRH VXXJD XMSIN BXUGI UPVRG ESQSG YKQOK LMXRS IBZAL BAYJM AYAVB XRSIC KKPYH ULWFU YHBPG VIGNX WBIQP RGVXY SSBEL NZLVW IMQMG YGVSW GPWGG NARSP TXVKL PXWGD XRJHU SXQMI VTZYO GCTZR JYVBK MZHBX YVBIT TPVTM OOWSA IERTA SZCOI TXXLY JAZQC GKPCS LZRYE MOOVC HIEKT RSREH MGNTS KVEPN NCTUN EOFIR TPPDL YAPNO GMKGC ZRGNX ARVMY IBLXU QPYYH GNXYO ACCIN QBUQA GELNR TYQIH LANTW HAYCP RJOMO KJYTV SGVLY RRSIG NKVXI MQJEG GJOML MSGNV VERRC MRYBA GEQNP RGKLB XFLRP XRZDE JESGN XSYVB DSSZA LCXYE ICXXZ OVTPW BLEVK ZCDEA JYPCL CDXUG MARML RWVTZ LXIPL PJKKL CIREP RJYVB ITPVV ZPHCX FPCRG KVPSS CPBXW VXIRS SHYTU NWCGI ANNUN VCOEA JLLFI LECSO OLCTG CMGAT SBITP PNZBV XWUPV RIHUM IBPHG UXUQP YYHNZ MOKXD LZBAK LNTCC MBJTZ KXRSM FSKZC SSELP UMARE BCIPK GAVCY EXNOG LNLCC JVBXH XHRHI AZBLD LZWIF YXKLM PELQG RVPAF ZQNVK VZLCE MPVKP FERPM AZALV MDPKH GKKCL YOLRX TSNIB ELRYN IVMKP ECVXH BELNI OETUX SSYGV TZARE RLVEG GNOQC YXFCX YOQYO ISUKA RIQHE YRHDS REFTB LEVXH MYEAJ PLCXK TRFZX YOZCY XUKVV MOJLR RMAVC XFLHO KXUVE GOSAR RHBSS YHQUS LXSDJ INXLH PXCCV NVIPX KMFXV ZLTOW QLKRY TZDLC DTVXB ACSDE LVYOL BCWPE ERTZD TYDXF AILBR YEYEG ESIHC QMPOX UDMLZ VVMBU KPGEC EGIWO HMFXG NXPBW KPVRS XZCEE PWVTM OOIYC XURRV BHCCS SKOLX XQSEQ RTAOP WNSZK MVDLC PRTRB ZRGPZ AAGGK ZIMAP RLKVW EAZRT XXZCS DMVVZ BZRWS MNRIM ZSRYX IEOVH GLGNL FZKHX KCESE KEHDI FLZRV KVFIB XSEKB TZSPE EAZMV DLCSY ZGGYK GCELN TTUIG MXQHT BJKXG ZRFEX ABIAP MIKWA RVMFK UGGFY JRSIP NBJUI LDSSZ ALMSA VPNTX IBSMO"

ciphertext = ciphertext.replace(' ', '')

# 0 indicates that it should calculate most likly key_length
key_length = 0

# for key length guessing if you want to use a different popular factor
factor_offset = 1

alphabet = string.ascii_lowercase

# most common letters with their percentages 
grams = {
    'e': 13,
    't': 9.1,
    'a': 8.2,
    'o': 7.5,
    'i': 7,
    'n': 6.7,
    's': 6.3,
    'h': 6.1,
    'r': 6,
    'd': 4.3,
    'l': 4,
    'c': 4,
    'u': 2.8,
    'm': 2.4,
    'w': 2.4,
    'f': 2.2,
    'g': 2,
    'y': 2,
    'p': 1.9,
    'b': 1.9,
    'v': 0.98,
    'k': 0.77,
    'j': 0.15,
    'x': 0.15,
    'q': 0.095,
    'z': 0.0074
}

# Get most popular factor out of a list of differences
# only includes factors from 3-20
def get_factor(differences):
    factor_count = {}
    for l in differences:
        for diff in l:
            for factor in range(3,20):
                if (diff / factor) % 1 == 0:
                    if factor in factor_count:
                        factor_count[factor] += 1
                    else:
                        factor_count[factor] = 1
    factor_count = sorted(factor_count.items(), key=lambda x: x[::-1], reverse=True)
    
    pop_factor = factor_count[factor_offset]
    print('Using factor: ', pop_factor[0])
    return pop_factor[0]


def get_key_length(text):
    patterns= {}
    for index in range(len(text)):
        for pattern_size in range(3, 6):
            check_pattern = ''
            if index + pattern_size > len(text):
                break
            for pattern_index in range(index, index + pattern_size):
               check_pattern += text[pattern_index] 

            if check_pattern in patterns:
                if type(patterns[check_pattern]) == int: 
                    patterns[check_pattern] = [(patterns[check_pattern], index)]
                else:
                    patterns[check_pattern].append((patterns[check_pattern][-1][1], index))
            else:
                patterns[check_pattern] = index

    def filter_pattern(pat):
        if type(pat[1]) != int and len(pat[1]) > 1:
            return True
        else:
            return False
    def differences(pat):
        return list(map(lambda x: x[1] - x[0], pat[1]))
    diffs = list(map(differences, filter(filter_pattern, patterns.items())))
    
    return get_factor(diffs)

            

if key_length == 0:
    key_length = get_key_length(ciphertext)


def decrypt_with_key(ctext, key):
    ptext = ''
    for i in range(len(ctext)):
        pchar = ctext[i].lower()
        kchar = key[i%len(key)].lower()
        index = (alphabet.index(pchar) - alphabet.index(kchar)) % 26
        ptext += alphabet[index]
    return ptext

def get_columns(text):
    columns = []
    for i in range(key_length):
        columns.append('')
    for i in range(len(text)):
        columns[i % key_length] += text[i]
    return columns

# reset to orignal format
def get_data(columns):
    ptext = ''
    for char_index in range(len(columns[0])):
        for column_index in range(key_length):
            column = columns[column_index]
            if char_index < len(column):
                ptext += column[char_index]
    return ptext

def get_count_map(text):
    count = {}
    for char in text:
        if char in count:
            count[char] += 1
        else:
            count[char] = 1
    return count 

# ceasar shift on text
def shift_text(text, offset):
    shifted_text = ''
    for char in text:
        shifted_char_index = (alphabet.index(char.lower()) - offset) % 26
        shifted_text += alphabet[shifted_char_index]
    return shifted_text


# decrypt ceasar cipher
def decrypt(ctext, offset_index=0):
    prob_texts = []
    for offset in range(26):
        prob_texts.append(shift_text(ctext, offset))

    chi_sums = []
    for (offset, prob_text) in enumerate(prob_texts):
        # print(prob_text)
        count_map = get_count_map(prob_text)
        chi_sum = 0
        for char in prob_text:
            expected_count = (grams[char] / 100) * len(ctext)
            current_count = 0
            if char in count_map: 
                current_count = count_map[char]
            chi = math.pow(current_count - expected_count, 2) / expected_count
            chi_sum += chi
        chi_sums.append((chi_sum, prob_text, offset))

    chi_sums = sorted(chi_sums, key=lambda x: x[0])
    # print(chi_sums)

    chosen_cipher =  chi_sums[offset_index]
    print('Choosing offset: ' + str(offset_index) + '. With key: ' + str(alphabet[chosen_cipher[2]]))
    print('Difference', chi_sums[1][0] - chi_sums[0][0] )

    return chosen_cipher[1]


def pretty_print(text):
    res = ''
    for char in text:
        if char.islower():
            res += '\033[93m' + char + '\033[0m'
        else:
            res += char
    print(res)

def map_columns(columns, custom_offsets=[]):
    pcolumns = []
    for i in range(len(columns)):
        if i < len(custom_offsets):
            pcolumns.append(decrypt(columns[i], custom_offsets[i]))
        else:
            pcolumns.append(decrypt(columns[i]))
    return pcolumns



columns = get_columns(ciphertext)

pcolumns = map_columns(columns) 

plaintext = get_data(pcolumns)

pretty_print(plaintext)

# plaintext = decrypt("aoljhlzhyjpwolypzvulvmaollhysplzaruvduhukzptwslzajpwolyzpapzhafwlvmzbizapabapvujpwolypudopjolhjoslaalypuaolwshpualeapzzopmalkhjlyahpuubtilyvmwshjlzkvduaolhswohila")
# print(plaintext)
