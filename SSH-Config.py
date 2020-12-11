import sys
import ipaddress
import pprint
pp = pprint.PrettyPrinter(indent=4)
SSH_status={'port': [22], 'AddressFamily': ['ipv4+ipv6'], 'IPv4-ListenAddress':[], 'IPv6-ListenAddress':[],
    'version':[],'Authentication':{'HostKey':[], 'PermitRootLogin': [], 'Version1_key_lifetime':['1h'], 
    'Version1_key_size':[1024], 'StrictModes': ['yes'],'LoginGraceTime':['2m'],'Maximum_Authentication_Tries':[6], 'Maximum_allowed_Sessions':[10],
    'Allow_Publik-key_Authentication':['yes'], 'Allowe_RSA_Authentication':['yes'],'Authorized_Keys_File_Location':['.ssh/authorized_keys'],
    'AuthorizedKeysCommand':['no'], 'AuthorizedKeysCommandUser':['no'], 'RhostsRSAAuthentication':['no'], 'HostbasedAuthentication':['no'], 
    'Authentication_type':['Authenticate_based_on_user&pass'], 'Kerberos_setting':{'Allow_kerberos_Authentication':['no'], 'Loacal_and_kerberos_Authentication':['yes']}} }
try:
    f=open('sshd_config')
    for j in range(sum(1 for line in open('sshd_config'))):
        linetext=f.readline().split()

        if 'Port' in linetext:
            SSH_status['port']=[]
            SSH_status['port']=linetext[1]


        if 'AddressFamily' in linetext:
            SSH_status['AddressFamily']=[]
            if 'any' in linetext:
                SSH_status['AddressFamily']='ipv4+ipv6'
            elif 'inet' in linetext:
                SSH_status['AddressFamily']='ipv4'
            elif 'inet6' in linetext:
                SSH_status['AddressFamily']='ipv6'


        if 'ListenAddress' in linetext and ipaddress.ip_address(linetext[1]).version==4:
    
            SSH_status['IPv4-ListenAddress'].append(linetext[1])
            
    

        if 'ListenAddress' in linetext and ipaddress.ip_address(linetext[1]).version==6:
                print(linetext[1])
                SSH_status['IPv6-ListenAddress'].append(linetext[1])
            

        if 'PermitRootLogin' in linetext:
            if 'yes' in linetext:
                SSH_status['Authentication']['PermitRootLogin']=True
            elif 'no' in linetext:
                SSH_status['Authentication']['PermitRootLogin']=False
            elif 'without-password' in linetext:
                SSH_status['Authentication']['PermitRootLogin']='Authentication based on SSH key'

        if 'Protocol' in linetext:
            
            SSH_status['version'].append(linetext[1])

        if 'HostKey' in linetext and '#' not in linetext:
            SSH_status['Authentication']['HostKey'].append(linetext[1])

        if 'KeyRegenerationInterval' in linetext:
            SSH_status['Authentication']['Version1_key_lifetime']=[]
            SSH_status['Authentication']['Version1_key_lifetime']=linetext[1]

        if 'ServerKeyBits' in linetext:
            SSH_status['Authentication']['Version1_key_size']=[]
            SSH_status['Authentication']['Version1_key_size']=linetext[1]   

        if 'LoginGraceTime' in linetext:
            SSH_status['Authentication']['Version1_key_lifetime']=[]
            SSH_status['Authentication']['Version1_key_lifetime']=linetext[1]

        if 'MaxAuthTries' in linetext:
            SSH_status['Authentication']['Version1_key_size']=[]
            SSH_status['Authentication']['Version1_key_size']=linetext[1]
            
        if 'MaxAuthTries' in linetext:
            SSH_status['Authentication']['Maximum_Authentication_Tries']=[]
            SSH_status['Authentication']['Maximum_Authentication_Tries']=linetext[1]

        if 'MaxSessions' in linetext:
            SSH_status['Authentication']['Maximum_allowed_Sessions']=[]
            SSH_status['Authentication']['Maximum_allowed_Sessions']=linetext[1]
        if 'RSAAuthentication' in linetext:
            SSH_status['Authentication']['Allowe_RSA_Authentication']=[]
            SSH_status['Authentication']['Allowe_RSA_Authentication']=linetext[1]
        if 'PubkeyAuthentication' in linetext:
            SSH_status['Authentication']['Allow_Publik-key_Authentication']=[]
            SSH_status['Authentication']['Allow_Publik-key_Authentication']=linetext[1]
        if 'AuthorizedKeysFile' in linetext:
            SSH_status['Authentication']['Authorized_Keys_File_Location']=[]
            SSH_status['Authentication']['Authorized_Keys_File_Location']=linetext[1]
        if 'AuthorizedKeysCommand' in linetext:
            SSH_status['Authentication']['Authorized_Keys_Command']=[]
            SSH_status['Authentication']['Authorized_Keys_Command']=linetext[1]
        if 'AuthorizedKeysCommandUser' in linetext:
            SSH_status['Authentication']['Authorized_Keys_Command_User']=[]
            SSH_status['Authentication']['Authorized_Keys_Command_User']=linetext[1]
        if 'RhostsRSAAuthentication' in linetext:
            SSH_status['Authentication']['Rhosts_RSA_Authentication_for_version2']=[]
            SSH_status['Authentication']['Rhosts_RSA_Authentication_for_version2']=linetext[1]
        if 'HostbasedAuthentication' in linetext:
            SSH_status['Authentication']['Host_based_Authentication_for_version2']=[]
            SSH_status['Authentication']['Host_based_Authentication_for_version2']=linetext[1]
            
        if 'PasswordAuthentication' in linetext and ('yes'in linetext or 'no'in linetext):
            SSH_status['Authentication']['Authentication_type']=[]
            if 'yes' in linetext:
                SSH_status['Authentication']['Authentication_type']=['Authenticate_based_on_user&pass']
            elif 'no' in linetext:
                SSH_status['Authentication']['Authentication_type']=['Authentication_based_on_key']

        if 'KerberosAuthentication' in linetext:
            SSH_status['Authentication']['Kerberos_setting']['Allow_kerberos_Authentication']=[]
            SSH_status['Authentication']['Kerberos_setting']['Allow_kerberos_Authentication']=linetext[1]
        if 'KerberosOrLocalPasswd' in linetext:
            SSH_status['Authentication']['Kerberos_setting']['Loacal_and_kerberos_Authentication']=[]
            SSH_status['Authentication']['Kerberos_setting']['Loacal_and_kerberos_Authentication']=linetext[1]


    
    
    if not SSH_status['IPv4-ListenAddress'] or '0.0.0.0' in SSH_status['IPv4-ListenAddress']:
        SSH_status['IPv4-ListenAddress']=[]
        SSH_status['IPv4-ListenAddress']=['0.0.0.0']

    if not SSH_status['IPv6-ListenAddress'] or '::' in SSH_status['IPv4-ListenAddress']:
        SSH_status['IPv6-ListenAddress']=['::']

    if not SSH_status['version']:
        SSH_status['version']=['2']

    pp.pprint(SSH_status)
    
    print('------------------------------')
    if SSH_status['port']=='22':
        print('Warning: For higher security you should change the default port value 22')

    if '1' in SSH_status['version']:
        print('Warning: For higher security you should active version 2 only')
    
    if '1' not in SSH_status['version'] or  '2' not in SSH_status['version'] :
        print('error: protocol version should be 1 or 2, the wrong value have been keyed in')

    if '0.0.0.0' in SSH_status['IPv4-ListenAddress']:
        print('Warning: there is not any limitation on host access')


except FileNotFoundError as err:
    print('Handling run-time error:', err)


