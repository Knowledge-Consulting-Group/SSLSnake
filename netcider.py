#!/usr/bin/python

##  Coded by:   Shawn Evans
##  Email:      Shawn.Evans@KnowledgeCG.com
##  Website:    www.Knowledgecg.com

#3-clause BSD License
#Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

#Redistributions of works must retain the original copyright notice, this list of conditions and the following disclaimer.
#Redistributions in binary form must reproduce the original copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#Neither the name of the W3C nor the names of its contributors may be used to endorse or promote products derived from this work without specific prior written permission.
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR #A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT #LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR #TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.   

import sys
import operator
import itertools
try:
    from functools import *
except:
    pass

class cidr():

    def __init__(self, address):
    
        try:
            index = address.index('/')
            self.base = address[:index]
            intMask = address[index+1:]
            self.netmask = self.netmask(intMask)
            self.wildcard = self.wildcard(intMask)
            self.binBase = self.addressToBin(self.base)    
            self.subnet = self.listToString(self.network(self.base, self.netmask))
            self.hostmin = self.hostMin(self.subnet)
            self.hostmax = self.hostMax(self.subnet, self.wildcard)
            self.total = self.numhosts(self.wildcard)
            self.broadcast = self.hostMin(self.hostmax)
            self.allips = self.getIpList(self.hostmin, self.hostmax) 
        except Exception as e:
            print(e) 
    
    def update(self, address):
        try:
            index = address.index('/')
            self.base = address[:index]
            intMask = address[index+1:]
            self.netmask = self.netmask(intMask)
            self.wildcard = self.wildcard(intMask)
            self.binBase = self.addressToBin(self.base)    
            self.subnet = self.listToString(self.network(self.base, self.netmask))
            self.hostmin = self.hostMin(self.subnet)
            self.hostmax = self.hostMax(self.subnet, self.wildcard)
            self.total = self.numhosts(self.wildcard)
            self.broadcast = self.hostMin(self.hostmax)
            self.allips = self.getIpList(self.hostmin, self.hostmax) 
        except Exception as e:
            print(e) 
    
    
    def toString(self):
        print('Base:\t\t%s') % self.base
        print('Netmask:\t%s') % self.netmask
        print('Wildcard:\t%s') % self.wildcard
        print('Broadcast:\t%s') % self.broadcast
        print('Subnet ID:\t%s') % self.subnet
        print('Host min:\t%s') % self.hostmin
        print('Host max:\t%s') % self.hostmax
        print('Total Hosts:\t%s') % self.total
    
    def getIpList(self, hostmin, hostmax):
        tmpmin = hostmin.split('.')
        tmpmax = hostmax.split('.') 
        ranges = [ range(i, j + 1) for i, j in zip(list(map(int, tmpmin)),list(map(int, tmpmax))) ]
        complete = [] 
        for ip in itertools.product(*ranges):
            complete.append( '.'.join(list(map(str, list(ip)))))
        return complete

    def numhosts(self, wildcard):
        tmpWild = list(map(int, wildcard.split('.')))
        ranges = list(map(lambda e: len(range(0, e + 1)), tmpWild))
        numhosts = reduce(operator.mul, ranges)-2
        return numhosts if numhosts > 0 else 1        

    def hostMin(self, address):
        temp = address.split('.')
        temp[3] = str(int(temp[3])+1)
        return self.listToString(temp)  
    
    def hostMax(self, address, wildcard):
        tmpAddr = address.split('.')
        tmpWild = wildcard.split('.')
        tmpWild[3] = str(int(tmpWild[3])-1)
        return self.listToString(list(map(sum, zip(list(map(int, tmpAddr)), list(map(int, tmpWild))))))
        
    def netmask(self, mask):
        binMask = '%s%s' % ('1'*int(mask), '0'*(32-int(mask)))
        maskList = list(map(''.join, zip(*[iter(binMask)] * 8)))
        netmask = self.binToAddress(maskList)
        return self.listToString(netmask)
        
    def wildcard(self, mask):
        binMask = '%s%s' % ('1'*int(mask), '0'*(32-int(mask)))
        maskList = list(map(''.join, zip(*[iter(binMask)] * 8)))
        netmask = self.binToAddress(maskList)
        wildcard = [ 255-val for val in netmask ]
        return self.listToString(wildcard)
 
    def listToString(self, ipList):
        return list(map('.'.join, [ list(map(str, ipList))] ))[0]
   
    def network(self, address, netmask):
        binNetwork = [ bin(int(a,2) & int(b,2))[2:].zfill(8) for a, b in zip(self.addressToBin(address), self.addressToBin(netmask))]
        return self.binToAddress(binNetwork)
     
    def addressToBin(self, address):
        return [ bin(int(val))[2:].zfill(8) for val in address.split('.') ]
    
    def printList(self):
        try:
            for ip in self.allips:
                print(ip)
        except Exception as e:
            print(e)

    def binToAddress(self, binAddress):
        return [ int(val,2) for val in binAddress ]
    
def usage():
    title = 'Net Cider v1.0 beta'
    author = 'Shawn Evans'
    email = 'Shawn.Evans@Knowledgecg.com'
    print('')
    print('='*61)
    print('='*((59-len(title))/2), title,'='*((59-len(title))/2))   
    print('='*((59-len(author))/2), author,'='*((59-len(author))/2))
    print('='*((59-len(email))/2), email,'='*((59-len(email))/2))
    print('='*61)
    print('')
    print('-o\tOutput full IP range to stdout')
    print('')
    print('Example:')
    print('$ python netCider.py 192.168.0.2/24')
    print('$ python netCider.py -o 192.168.0.2/24')
    print('')

if __name__ == '__main__':
    
    ipLocation = reduce(lambda x, y: x + y, [ i if (val.find('.') > 0 and val.find('/')) > 0 else 0 for i, val in enumerate(sys.argv) ])  
        
    if ipLocation > 0:  
        cidrIP = cidr(sys.argv[ipLocation])
    else:
        usage()
        sys.exit()
        
    if '-o' in sys.argv:
        cidrIP.printList()
        sys.exit()
    else:
        cidrIP.toString() 
           
     
