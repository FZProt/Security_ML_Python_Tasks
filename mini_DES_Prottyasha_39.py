### MINI DES_ PROTTYASHA_ 170042039



import collections

def subkey_generation(inp_key,pc1_table,pc2_table,iteration_table):
    subkey_list = list()
    pc1_transformed = table_transformation(pc1_table,inp_key)
    print("Reordered using PC-1: ", pc1_transformed)
    for i in range(1,len(iteration_table)+1):
        print("\n\nSUBKEY GENERATION - ROUND ",i)
        print("------------------------------------------------")
        half = int(len(pc1_transformed)/2)
        c = pc1_transformed[:half]
        print("\nC: ",c)
        d = pc1_transformed[half:]
        print("D: ",d)
        cdq = collections.deque(c)
        ddq = collections.deque(d)
        for j in range(iteration_table[i-1]):
            leftmost_c = cdq.popleft()
            leftmost_d = ddq.popleft()
            cdq.append(leftmost_c)
            ddq.append(leftmost_d)
        c = list(cdq)
        d = list(ddq)
        print("\nAfter left shift: ")
        print("     C: ",c)
        print("     D: ",d)
        pc1_transformed = c+d
        pc2_transformed = table_transformation(pc2_table, pc1_transformed)
        print("\nReordered using PC-2: ", pc2_transformed)
        subkey = pc2_transformed
        subkey_list.append(subkey)
        print("**** SUBKEY ",i,": ", subkey)
    return subkey_list


def encryption(pt, subkeys_list, ip_table, expansion_table, s1_table, s2_table, s3_table, permutation_table, ip_inverse_table, iteration_table):
    ip_transformed = table_transformation(ip_table, pt)
    print("Reordered using IP: : ", ip_transformed)
    counter=1
    for subkey in subkeys_list:
        halflen=int(len(ip_transformed)/2)
        lh = ip_transformed[:halflen]
        rh = ip_transformed[halflen:]
        print("\nENCRYPTION ROUND - ",counter)
        print("------------------------------------------------------")
        print("\nLH: ",lh)
        print("RH: ",rh)
        e_transformed_rh = table_transformation(expansion_table, rh)
        print("\nRH Reordered using E-table: ", e_transformed_rh)
        xor_result = xor_operation(subkey, e_transformed_rh)
        print("Xor with subkey ",counter,": ", xor_result)
        sbox_output = sbox_calc(xor_result, s1_table, s2_table, s3_table)
        print("Sbox_output: ",sbox_output)
        pbox_output = table_transformation(permutation_table, sbox_output)
        print("Pbox_output: ",pbox_output)
        p_xor_lh = xor_operation(pbox_output,lh)
        print("P_xor_LH: ", p_xor_lh)
        current_ciphertext = p_xor_lh + rh
        ip_transformed = rh + p_xor_lh
        print("\n**** Current_ciphertext(BEFORE SWAP): ", current_ciphertext)
        counter=counter+1
    ip_inversed = table_transformation(ip_inverse_table, current_ciphertext)
    print("\n---------------------------------------------")
    print("\nReordered using IP INVERSE table: ", ip_inversed)
    return ip_inversed


def decryption(ciphertext_final, subkeys_list, ip_table, expansion_table, s1_table, s2_table, s3_table, permutation_table, ip_inverse_table, iteration_table):
    ip_transformed = table_transformation(ip_table, ciphertext_final)
    print("Reordered using IP: : ", ip_transformed)
    counter=1
    reverse_counter=len(subkeys_list)
    for subkey in reversed(subkeys_list):
        halflen=int(len(ip_transformed)/2)
        lh = ip_transformed[:halflen]
        rh = ip_transformed[halflen:]
        print("\nDECRYPTION ROUND - ",counter)
        print("------------------------------------------------------")
        print("\nLH: ",lh)
        print("RH: ",rh)
        e_transformed_rh = table_transformation(expansion_table, rh)
        print("\nRH Reordered using E-table: ", e_transformed_rh)
        xor_result = xor_operation(subkey, e_transformed_rh)
        print("Xor with subkey ",reverse_counter,": ", xor_result)
        sbox_output = sbox_calc(xor_result, s1_table, s2_table, s3_table)
        print("Sbox_output: ",sbox_output)
        pbox_output = table_transformation(permutation_table, sbox_output)
        print("Pbox_output: ",pbox_output)
        p_xor_lh = xor_operation(pbox_output,lh)
        print("P_xor_LH: ", p_xor_lh)
        current_plaintext = p_xor_lh + rh
        ip_transformed = rh + p_xor_lh
        print("\n**** Current_plaintext(BEFORE SWAP): ", current_plaintext)
        counter=counter+1
        reverse_counter=reverse_counter+1
    ip_inversed = table_transformation(ip_inverse_table, current_plaintext)
    print("\n---------------------------------------------")
    print("\nReordered using IP INVERSE table: ", ip_inversed)
    return ip_inversed

###########################################################################
## SMALL HELPING FUNCTIONS
###########################################################################
def table_transformation(table, subject):
    transformed = list()
    for index in table:
        #print(subject[index-1])
        transformed.append(subject[index-1])
    return transformed


def xor_operation(a,b):
    xor_result = list()
    for i in range(len(a)):
        if a[i]==b[i]:
            xored_bit = 0
        else:
            xored_bit = 1
        xor_result.append(xored_bit)
    return xor_result


def sbox_calc(xor_result, s1_table, s2_table, s3_table):
    sbox_output=list()
    B_len = int(len(xor_result)/3)
    B1 = xor_result[:B_len]
    B2 = xor_result[B_len:(2*B_len)]
    B3 = xor_result[(2*B_len):]
    #print("B1: ",B1,"B2: ",B2, "B3: ",B3)

    rowb1 = int(binToDecimal( make_list_a_single_str( str(B1[0]) + str(B1[5]) )))
    colb1 = int(binToDecimal( make_list_a_single_str( str(B1[1]) + str(B1[2]) + str(B1[3]) + str(B1[4]) )))
    rowb2 = int(binToDecimal( make_list_a_single_str( str(B2[0]) + str(B2[5]) )))
    colb2 = int(binToDecimal( make_list_a_single_str( str(B2[1]) + str(B2[2]) + str(B2[3]) + str(B2[4]) )))
    rowb3 = int(binToDecimal( make_list_a_single_str( str(B3[0]) + str(B3[5]) )))
    colb3 = int(binToDecimal( make_list_a_single_str( str(B3[1]) + str(B3[2]) + str(B3[3]) + str(B3[4]) )))

    s1_val = make_n_bits(decToBinary(s1_table[rowb1][colb1]),4)
    s2_val = make_n_bits(decToBinary(s2_table[rowb2][colb2]),4)
    s3_val = make_n_bits(decToBinary(s3_table[rowb3][colb3]),4)
    s_val = s1_val+s2_val+s3_val
    #print("sval: ",s_val)
    for i in s_val:
        sbox_output.append(int(i))
    return sbox_output


###############################################################################
# SOME BASIC FUNCTIONS
###############################################################################
def make_list_a_single_str(li):
    strings = [str(integer) for integer in li]
    a_string = "".join(strings)
    #print("a str: ",a_string)
    return a_string

#takes binary string list, returns integer
def binToDecimal(bin):
    binlen = len(bin)
    count=1
    for i in range(1, binlen):
        count = count*2
    decimal = 0
    for bit in bin:
        dec=int(bit)*count
        decimal = decimal + dec
        count=count/2
    return decimal

#returns binary int list, takes integer
def decToBinary(num):
    binarylist=list()
    binarystr= str(bin(num)[2:])
    for i in binarystr:
        binarylist.append(int(i))
    return binarylist

#takes hex string, returns binary int list
def hexToBin(hex):
    hex = hex.lower()
    binlist = list()
    for h in hex:
        if h=='a':
            binlist=binlist+make_n_bits(decToBinary(10), 4)
        elif h=='b':
            binlist=binlist+make_n_bits(decToBinary(11), 4)
        elif h=='c':
            binlist=binlist+make_n_bits(decToBinary(12), 4)
        elif h=='d':
            binlist=binlist+make_n_bits(decToBinary(13), 4)
        elif h=='e':
            binlist=binlist+make_n_bits(decToBinary(14), 4)
        elif h=='f':
            binlist=binlist+make_n_bits(decToBinary(15), 4)
        else:
            binlist=binlist+make_n_bits(decToBinary(int(h)), 4)
    return binlist

#takes binary int list, returns hex string
def binToHex(binlist):
    hexstr = ''

    while len(binlist)>0:
        bin4bitstrlist = list()
        singleBitHexStr = ''
        for i in range(0,4):
            bin4bitstrlist.append(str(binlist[i]))
        decval = binToDecimal(bin4bitstrlist)
        if decval<10:
            singleBitHexStr=singleBitHexStr+str(int(decval))
        else:
            if decval==10:
                singleBitHexStr=singleBitHexStr+'A'
            elif decval==11:
                singleBitHexStr=singleBitHexStr+'B'
            elif decval==12:
                singleBitHexStr=singleBitHexStr+'C'
            elif decval==13:
                singleBitHexStr=singleBitHexStr+'D'
            elif decval==14:
                singleBitHexStr=singleBitHexStr+'E'
            elif decval==15:
                singleBitHexStr=singleBitHexStr+'F'
        hexstr=hexstr+singleBitHexStr
        binlist = binlist[4:]
    return hexstr



#takes binary list and sequence length, returns binary int list
def make_n_bits(binlist,length):
    dqbl=collections.deque(binlist)
    diff=length-len(binlist)
    if diff!=0:
        for i in range(diff):
            dqbl.appendleft(0)
    return list(dqbl)









def main():
    iteration_table = [1,1,2,2,2,2]
    ip_table = [18,10,2,20,12,4,22,14,6,24,16,8,17,9,1,19,11,3,21,13,5,23,15,7]
    expansion_table = [12,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,1]
    permutation_table = [7,12,1,5,10,2,8,3,9,6,11,4]
    pc1_table = [17,9,1,18,10,2,19,11,3,23,15,7,22,14,6,21,13,5,20,12,4]
    pc2_table = [17,11,1,5,3,15,6,18,10,19,12,4,8,16,9,20,13,2]
    ip_inverse_table = [15,3,18,6,21,9,24,12,14,2,17,5,20,8,23,11,13,1,16,4,19,7,22,10]

    s1_table = [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
                [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
                [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
                [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]]

    s2_table = [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
                [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
                [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
                [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]]

    s3_table = [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
                [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
                [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
                [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]]
    ptxt = input("Enter plaintext (in hex):")
    pt = hexToBin(ptxt)
    #pt = make_n_bits(ptxt,24)
    print(pt)

    key = input("Enter key (in hex):")
    inp_key = hexToBin(key)
    print(inp_key)

    print("\n\nSUBKEY GENERATION")
    print("=========================================================")
    subkeys_list = list()
    subkeys_list = subkey_generation(inp_key,pc1_table,pc2_table,iteration_table)
    #print("subkeys: ",subkeys_list)

    #ciphertext_list = list()
    print("\n\n=========================================================")
    print("\nENCRYPTION PROCESS")
    print("=========================================================")
    ciphertext_final = encryption(pt, subkeys_list, ip_table, expansion_table, s1_table, s2_table, s3_table, permutation_table, ip_inverse_table, iteration_table)
    final_ct = binToHex(ciphertext_final)
    print("#### FINAL CIPHERTEXT: ",final_ct)
    print("\n\n=========================================================")
    print("\nDECRYPTION PROCESS")
    print("=========================================================")
    plaintext_final = decryption(ciphertext_final, subkeys_list, ip_table, expansion_table, s1_table, s2_table, s3_table, permutation_table, ip_inverse_table, iteration_table)
    final_pt = binToHex(plaintext_final)
    print("#### FINAL PLAINTEXT: ",final_pt)


if __name__ == "__main__":
    main()
