#This program was used to help me with determining the length of the key that was used to encrypt the ciphertext given. 
#The program does not determine the key itself. 

#importing a library to help me separate the ciphertext into n-character chunks. This library does not directly solve the problem.
from textwrap import wrap

ciphertext = 'NBLRFMGYMYNUAGJKGRWPHIGISHTXHHLBQQVHCGZXVBHONVRVAFJYGUIGXTIEPMWTILFRKBJHSZRAMAWMVETRGMYADJENBAHEQJZWNBXAWNUCGDTVTAGHQQVFHCBQATSRZNFQENHUGLVZGFINGMVTAGRUKXFGMHFPBYWMVPXHWHUAWNHWCOEJTHGOFRFWGTASNQLHZFHNWQHSOFFHKNWWNLWWAFJYFWZHSUYAFZRUHCBQAMFBXNULLYVYQHDXQCJZHVMFBXERJNXHUQRXMNCHBIAMWCHTHVVWMJGLWGNGUXHGMTCFGRAXHILRFWFRSLPHIGIHLNGMLFTYTXIKIDLVYIMJWHSRZFFHCBQXKTAIGHNKJSYKSZXXGCBQIGIOMFRKBFHCBQIGIGNEHVZYVYAFGUJFMRFCKNHSGKMWJDUEWUXSHCFRVMMSZERVMQWHRVWYYVYSLOAYOANLVLYQSOHZVWWGRDVWBSEAREYNFMGKIGIHBRGIFFUYGKIMHOHOHKTZGYQEGMMCMRZPHJLJYRQMAIFAHZTGZYNQLBSGYPXZXXMMGHULBSMHSXHWHUAGMGHCOEDOXYVYHVMHKGYPXZXSSNJRZDXHICUMOJBNPBJXWHBEHIMXHIBXZVWWNVFIESONVRVTQWHSUILYFOPWCKJCOELVMJZFRFBNFZJERXXWHSNQLHZFXNWILTOMGRXKTAIGHWNWCPRUIEQGUSHBRFAYELKTSQCGLHXSGWNUMWJSJYBIUTINCUQOFQSNQLKNUBGOGLTAUABKHRDUALMLMOPREMXSFYFSWGIWHTWWTROLXHBWJAUAGNHWDLBGCVYGUAGAXWJCPHAMMONCUWMJQNGKMIWWPNFGTSRMRFCKNHSBIBAJWLPXAMTAYEVBANGBNVOXSSLNWMWUCMVWQOJWHARDTYWIAWPTYVUFEMXSQLHFQTQHIGKMWNUCGDTXHCHBPGPJHIBFIKJOVBXBMMSMRLUITFNNQBIWWHPLXEJGCAGMXIWNVVWNWCVYLOTYWIAWWNUVIYGKBAWFYLJXWHCRVQGHZOQLVZYVYELOAYHICUQOFQSJHPTASUYZIRXFYFSMVYSXGKMYZBXNPMGYOFELOAYCZCHWIQSNBHVZFUYVQXKNJUGHKHRAOALKTYWIAVZXLOLQOMLXCZGKMFJRCHPWKYSWUQWETUSJKMMMSLVWQLNBMGDVMRSMFDOXXHYKWAHWCFQIILMWIAHLEJHNRUAVNHCMHVLMOPRWPXWWAUWBHHCGZXVB'

#function used to list the divisors of a given number
def getDivisors(n):
    l = []
    for i in range(2,n):
        if n % i == 0:
            l.append(i)
    return l

#function used to determine the offset of ever 3-character pattern in the ciphertext
def tupleOffset(l):
    i = 0
    offset = []
    div = []
    while i < len(l): #loop through whole ciphertext
        tuple1 = l[i:i+3] #take a 3-character tuple
        tupleLenth = len(tuple1)
        if tupleLenth == 3: #if not 3, then we've reached the end of ciphertext
            for j in range(i+1, len(l)): #trying to find same pattern of 3-character tuple
                tuple2 = l[j:j+3]
                if tuple1 == tuple2:
                    diff = j - i #get their offset
                    offset.append(int(diff)) #write it onto the list
                    divi = getDivisors(diff)
                    div.append(getDivisors(diff))
                    #print('pattern: ' + str(tuple2) + '\n' + 'offset: ' + str(diff) + '\n' + 'divisors: ' + str(divi) +'\n')
        i = i + 1
    return offset, div
    
#function used to find the most common divisor by counting the frequency of each divisor
def getFrequency(d):
    #just want frequencies for divisors 1 < x <= 15, since keys are desireably short
	#the index represents the divisor, the value represents the frequency
	freqList = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
	i = 0
	while i < len(d):
		for j in d[i]:
			if j < len(freqList):
				freqList[j] = freqList[j] + 1
		i = i + 1
	return freqList

#put the offset of each matching 3-character tuple in a list and put the divisor of each offset into another list    
offset, divisors = tupleOffset(split(ciphertext))

#print(getFrequency(divisors)) #test

#printing the frequencies of divisors 1 < x <= 15
print('frequencies of divisors from 2 - 15:')
freqs = getFrequency(divisors)
i = 2
while i < len(freqs):
    print(str(i) + ': ' + str(freqs[i]))
    i = i + 1

maxFreq = max(freqs)
keyLength = freqs.index(maxFreq) #index corresponds to the divisor
print('\nKey length is ' + str(keyLength) + '\n')

#now we split the ciphertext into chunks with legth of keyLength
splitCipher = wrap(ciphertext, keyLength)
#print(splitCipher)

#This loop just counts the number of letters on the ciphertext
#used to create the hitograms
final = []
for i in range(0, 26): #for every 26 letters in the alphabet
    row = []
    for k in range(0, keyLength): 
	    count = 0
	    for l in range(0, len(splitCipher)): #scanning through whole ciphertext
	        text = splitCipher[l]
	        if text[k] == chr(65+i):
	            #print(chr(65+i))
	            #print('match!')
	            count = count + 1
	    row.append(int(count))
    final.append(row)

#just printing the histogram
print('\nHistograms:')
for s in range (0,len(final)):
    print(chr(65+s) + ': ' + str(final[s]))