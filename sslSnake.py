#!/usr/bin/python3

##  Coded by:   Shawn Evans
##  Email:      Shawn.Evans@KnowledgeCG.com
##  Website:    www.Knowledgecg.com

#3-clause BSD License
#Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

#Redistributions of works must retain the original copyright notice, this list of conditions and the following disclaimer.
#Redistributions in binary form must reproduce the original copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#Neither the name of the W3C nor the names of its contributors may be used to endorse or promote products derived from this work without specific prior written permission.
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR #A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT #LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR #TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.      

import os
import ssl
import socket
import re
import sys
import pprint 
import netcider


tmp = '/tmp/sslsnake.pem'
title = 'SSLSnake'
version = 'v.9.4 beta'
email = 'Shawn.Evans@knowledgecg.com'
author = 'Shawn Evans'
description = 'Python based SSL cipher checker'

class SSLChecker():

    def __init__(self, host, port, types, verbose):
        highCiphers = [re.split('\ +',cipher.strip()) for cipher in os.popen('openssl ciphers -v "HIGH" 2> /dev/null').read().split('\n')]
        medCiphers = [re.split('\ +',cipher.strip()) for cipher in os.popen('openssl ciphers -v "MEDIUM" 2> /dev/null').read().split('\n')]
        lowCiphers = [re.split('\ +',cipher.strip()) for cipher in os.popen('openssl ciphers -v "LOW:EXP" 2> /dev/null').read().split('\n')]
        sslv2Ciphers = [re.split('\ +',cipher.strip()) for cipher in os.popen('openssl ciphers -v "SSLv2" 2> /dev/null').read().split('\n')]
        anonCiphers = [re.split('\ +',cipher.strip()) for cipher in os.popen('openssl ciphers -v "aNULL" 2> /dev/null').read().split('\n')]
        clearCiphers = [re.split('\ +',cipher.strip()) for cipher in os.popen('openssl ciphers -v "eNULL" 2> /dev/null').read().split('\n')]
        self.complete = {'HIGH':highCiphers,'MEDIUM':medCiphers,'LOW':lowCiphers,'SSLv2':sslv2Ciphers,'aNULL':anonCiphers,'eNULL':clearCiphers}
        
        self.checkSSLv2 = False
        self.sslv2Context = None
 
        if verbose:
            self.verbose = True
        else:
            self.verbose= False  
        
        self.setHost(host, port) 
       
        if 'SSLv2' in types:
            self.checkSSLv2= True 
            try:
                self.sslv2Context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
                self.sslv2Context.options |= ssl.OP_NO_SSLv3
                self.sslv2Context.set_default_verify_paths()
                self.sslv2Context.verify_mode = ssl.CERT_OPTIONAL
            except AttributeError as e:
                print('[ERROR]\tSSLv2 ciphers are not supported')
                types.remove('SSLv2')
            except IOError as e:
                print('[ERROR]\tCannot open certificate bundle, you might be using Python 2.7 or earlier')
                sys.exit()
                print(e)
            except Exception as e:
                print(e)
                sys.exit()
            
        try:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            self.context.options |= ssl.OP_NO_SSLv2
            self.context.verify_mode = ssl.CERT_OPTIONAL
            self.context.set_default_verify_paths()
            self.checks = types
        except IOError as e:
            print('[ERROR]\tCannot open certificate bundle') 
            sys.exit()
        except AttributeError as e:
            print('[ERROR]\tCannot open certificate bundle, you might be using Python 2.7 or earlier')
            sys.exit()

        self.supported = []
         
    def setHost(self, host, port):
        self.host = host    
        try:
            self.port = int(port)
        except ValueError:
            print('[ERROR]\tInvalid port value.')
            sys.exit()
        
        self.portOpen = self.isOpen(self.host, self.port)
    
 
    def checkCiphers(self):
        for cipherType in self.checks:
            if cipherType in self.complete.keys():
                for cipher in self.complete[cipherType]:
                    if len(cipher) == 1:
                        continue
                    if len(cipher) == 6:
                        name,prot,keyEx,auth,strength,mac = cipher
                    else:
                        name,prot,keyEx,auth,strength,mac,exp = cipher
                    
                    try:
                        strength = re.search('[0-9]{2,4}',strength).group(0)
                    except:
                        strength = 'None'
                    
                    try:
                        if self.checkSSLv2 and prot == 'SSLv2':
                            self.sslv2Context.set_ciphers(name)
                        else:  
                            self.context.set_ciphers(name)
                    except Exception as e:
                        continue
        
                    self.sslConnect(name, prot, strength, cipherType, keyEx, 2)
                    
            else:
                print('[ERROR]\tInvalid cipher list')
        
        for supCipher in self.supported:
            name, prot, strength, keyEx, cipherType = supCipher
            print('[ACCEPTED]\t%s\t%s\t%s\t%s\t%s\t%s:%s' % (name.ljust(25), prot, strength, keyEx, cipherType, self.host, self.port))
        self.supported = []

    def sslConnect(self, name, prot, strength, cipherType, keyEx, timeout):    
        if (self.checkSSLv2 and prot == 'SSLv2'):
            sslSock = self.sslv2Context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) 
        else:
            sslSock = self.context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        if self.portOpen: 
            try:
                sslSock.settimeout(timeout)
                sslSock.connect((self.host, self.port))
                self.supported.append([name,prot,strength,keyEx,cipherType])
            except socket.gaierror:
                print('[ERROR]\tUnable to connect to host %s' % self.host)
            except ssl.SSLError as e:
                if self.verbose:
                    print('[FAILURE]\t%s\t%s\t%s\t%s' % (name.ljust(25), prot, strength, cipherType))
            except socket.error as e:
                if self.verbose:
                    print('[ERROR]\tConnection reset by peer, cipher not supported.  Cipher: %s\tHost:%s' % (name,self.host))
            except Exception as e: 
                print(type(e))
                print(e)
            sslSock.close() 
    
    def hostnameMatch(self):
        if self.portOpen:
            try:
                self.context.set_ciphers('DEFAULT')
                sslSock = self.context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                sslSock.settimeout(1) 
                sslSock.connect((self.host, self.port))
                cert = sslSock.getpeercert()
                if self.verbose:
                    print('[INFO]\tCertificate data: ')
                    print(pprint.pformat(cert))
                ssl.match_hostname(cert, self.host)
            except socket.timeout:
                print('[ERROR]\tConnection timeout, verify host and port: %s:%s') % (self.host, self.port)
            except ssl.SSLError as e:
                print(e)
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                print('[INFO]\tSSL related connection error on %s:%s.' % (self.host, self.port))
                if self.verbose:
                    print('[INFO]\tUsing workaround to get cert data....')
                    cert = ssl.get_server_certificate((self.host, self.port)) 
                    open(tmp,'w+').write(cert)
                    print(os.popen(('cat %s | openssl x509 -text -noout') % (tmp)).read())
            except socket.gaierror:
                print('[ERROR]\tUnable to connect to host %s' % self.host)
                pass
            except socket.error as e:
                if self.verbose:
                    print('[ERROR]\tConnection reset by peer: ', self.host)
                print(e)
            except ssl.CertificateError:
                for value in cert['subject']:
                    if 'commonName' in value[0]:
                        common = value[0][1]
                print('[INFO]\tHost %s does not match common name %s' % (self.host, common))
            sslSock.close()
            
    def isOpen(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if self.verbose:
            print('[INFO]\tTrying %s:%s' % (ip, port))  
        try:
            s.connect((ip, int(port)))
            s.close()
            if self.verbose:
                print('[INFO]\tport: %s\thost: %s OPEN' % (port, ip))
            return True
        except Exception as e:
            if self.verbose:
                print('[INFO]\tException encountered: %s' % e)
            return False       

def usage():
    titleGap = int((60-(len('%s %s' % (title, version))))/2)
    authorGap = int((60-(len('%s - %s' % (author, email))))/2)
    descGap = int((60-(len(description)))/2)
    print('') 
    print('*'*61)
    print('%s %s %s %s' % ('='*titleGap, title, version,'='*titleGap))
    print('%s %s %s' % ( '='*descGap, description, '='*descGap))
    print('%s %s - %s %s' % ('='*authorGap, author, email, '='*authorGap))
    print('*'*61)
    print('')
    print('-?\tthis junk')
    print('-h\thost or ip')
    print('-f\thost file')
    print('-p\tport (default 443)')
    print('-all\tevery supported cipher')
    print('-high\thigh grade ciphers')
    print('-med\tmedium grade ciphers')
    print('-low\tlow grade ciphers')
    print('-sslv2\tsslv2 ciphers')
    print('-anon\tnull authentication ciphers')
    print('-clear\tclear-text ciphers')
    print('-v\tverbose output (print cert details)')
    print('')
    print('Example:')
    print('python %s -h www.example.com -low -ssl2 -v' % sys.argv[0])
    print('')
    print('Hit me up to complain: %s' % email) 
    sys.exit()


if __name__ == '__main__':
    cipherTypes = []
    host = ''
    port = 443
    verbose = False
    hostList = None

    if '-?' in sys.argv: usage()
    if '-h' in sys.argv:
        try:
            host = sys.argv[sys.argv.index('-h')+1]
            if host.find('/') > 0:
                cidrHost = netcider.cidr(host)
                hostList = cidrHost.allips
        except Exception as e:
            print('[ERROR]\tMissing value for host argument')
            usage()
    elif '-f' in sys.argv:
        try:
            hostList = open(sys.argv[sys.argv.index('-f')+1]).readlines()
            print('[INFO]\tUsing file as source')
        except Exception as e:
            print('[ERROR]\tInvalid host file')
            usage()
            sys.exit()
    elif not sys.stdin.isatty():
        hostList = sys.stdin.readlines()
    else:
        print('[ERROR]\tMissing host')
        usage()
        sys.exit()

    if '-p' in sys.argv:
        try:
            port = int(sys.argv[sys.argv.index('-p')+1])
        except:
            print('[ERROR]\tInvalid value for port argument')
            usage()
            sys.exit()

    if '-v' in sys.argv: verbose = True
    
    if '-high' in sys.argv: cipherTypes.append('HIGH')
    if '-low' in sys.argv: cipherTypes.append('LOW')
    if '-med' in sys.argv: cipherTypes.append('MEDIUM')
    if '-sslv2' in sys.argv: cipherTypes.append('SSLv2')
    if '-anon' in sys.argv: cipherTypes.append('aNULL')
    if '-clear' in sys.argv: cipherTypes.append('eNULL')
    if '-all' in sys.argv: cipherTypes.extend(['HIGH','MEDIUM','LOW','SSLv2','aNULL','eNULL'])

    if len(cipherTypes) == 0:
        print('[INFO]\tNo valid filters supplied, using -all')
        cipherTypes.extend(['HIGH','MEDIUM','LOW','SSLv2','aNULL','eNULL'])
    if hostList:
        for hostEntry in hostList:
            if hostEntry.find('/') > 0:
                try:
                    cidrHost.update(hostEntry)
                except NameError:
                    cidrHost = netcider.cidr(hostEntry)
                
                cidrHostList = cidrHost.allips
                for host in cidrHostList:
                    try:
                        sslChecker.setHost(host, port)
                    except NameError:
                        sslChecker = SSLChecker(host, port, cipherTypes, verbose)
                    sslChecker.hostnameMatch()
                    sslChecker.checkCiphers()


            if ':' in hostEntry:
                host = hostEntry.strip().split(':')[0]
                port = hostEntry.strip().split(':')[1]
            else:
                host = hostEntry.strip()
            
            try:
                sslChecker.setHost(host, port)
            except NameError:
                sslChecker = SSLChecker(host, port, cipherTypes, verbose)
            sslChecker.hostnameMatch()
            sslChecker.checkCiphers()
    else:   
        sslChecker = SSLChecker(host, port, cipherTypes, verbose)
        sslChecker.hostnameMatch()
        sslChecker.checkCiphers()

