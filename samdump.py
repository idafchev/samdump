#!/usr/bin/env python
from Registry import Registry
import binascii
import struct
from Crypto.Cipher import AES
from Crypto.Cipher import DES

'''
References:
https://github.com/gentilkiwi/mimikatz
http://www.insecurity.be/blog/2018/01/21/retrieving-ntlm-hashes-and-what-changed-technical-writeup/
https://microsoft.public.platformsdk.security.narkive.com/EkMyQZrb/maximum-size-of-sid
https://acad.ro/sectii2002/proceedings/doc2013-3s/05-OPREA.pdf
http://www.beginningtoseethelight.org/ntsecurity/index.htm
https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py
enum size
bool size
'''


# Redacted the registry.py file , key class to add class

class SAM_HASH_AES:
	def __init__(self, buf, offset):
		self.buf = buf[offset:]
		self.pekid		= struct.unpack_from(str("<H"), self.buf,0)[0]
		self.revision		= struct.unpack_from(str("<H"), self.buf,2)[0]
		self.data_offset	= struct.unpack_from(str("<I"), self.buf,4)[0]
		self.salt		= struct.unpack_from(str("<16s"), self.buf,8)[0]
		self.data		= buf[24:]

class SAM_ENTRY:
	def __init__(self, buf, offset):
		self.buf = buf[offset:]
		self.offset 	= struct.unpack_from(str("<I"), self.buf,0)[0]
		self.length 	= struct.unpack_from(str("<I"), self.buf,4)[0]
		self.unk	= struct.unpack_from(str("<I"), self.buf,8)[0]

class USER_ACCOUNT_V:
	def __init__(self, buf, offset):
		self.buf = buf[offset:]
		self.unk0_header	= SAM_ENTRY(buf,0)
		self.username		= SAM_ENTRY(buf,12)
		self.fullname		= SAM_ENTRY(buf,24)
		self.comment		= SAM_ENTRY(buf,36)
		self.user_comment	= SAM_ENTRY(buf,48)
		self.unk1		= SAM_ENTRY(buf,60)
		self.homedir		= SAM_ENTRY(buf,72)
		self.homedir_connect	= SAM_ENTRY(buf,84)
		self.script_path	= SAM_ENTRY(buf,96)
		self.profile_path	= SAM_ENTRY(buf,108)
		self.workstations	= SAM_ENTRY(buf,120)
		self.hours_allowed	= SAM_ENTRY(buf,132)
		self.unk2		= SAM_ENTRY(buf,144)
		self.lm_hash		= SAM_ENTRY(buf,156)
		self.ntlm_hash		= SAM_ENTRY(buf,168)
		self.ntlm_history	= SAM_ENTRY(buf,180)
		self.lm_history		= SAM_ENTRY(buf,192)
		self.data		= buf[204:]

class SAM_KEY_DATA:
	def __init__(self, buf, offset):
		self.buf = buf[offset:]
		self.revision		= struct.unpack_from(str("<I"), self.buf,0)[0]
		self.length		= struct.unpack_from(str("<I"), self.buf,4)[0]

	#	print "samkey_data", self.revision

class SAM_KEY_DATA_AES:
	def __init__(self, buf, offset):
		self.buf = buf[offset:]
		self.revision		= struct.unpack_from(str("<I"), self.buf,0)[0]
		self.length		= struct.unpack_from(str("<I"), self.buf,4)[0]
		self.check_len		= struct.unpack_from(str("<I"), self.buf,8)[0]
		self.data_len		= struct.unpack_from(str("<I"), self.buf,12)[0]
		self.salt		= struct.unpack_from(str('<16s'), self.buf,16)[0]
		self.data		= struct.unpack_from(str('>80s'), self.buf,32)[0]

class DOMAIN_ACCOUNT_F:
	def __init__(self, buf):
		self.buf = buf
		self.revision 				= struct.unpack_from(str("<H"), self.buf,0)[0]
		self.unk0 				= struct.unpack_from(str("<H"), self.buf,2)[0]
		self.unk1 				= struct.unpack_from(str("<I"), self.buf,4)[0]
		self.creation_time 			= struct.unpack_from(str("<q"), self.buf,8)[0]
		self.domain_modified_count 		= struct.unpack_from(str("<q"), self.buf,16)[0]
		self.max_password_age 			= struct.unpack_from(str("<q"), self.buf,24)[0]
		self.min_password_age 			= struct.unpack_from(str("<q"), self.buf,32)[0]
		self.force_logoff 			= struct.unpack_from(str("<q"), self.buf,40)[0]
		self.lockout_duration 			= struct.unpack_from(str("<q"), self.buf,48)[0]
		self.lockout_observation_windows 	= struct.unpack_from(str("<q"), self.buf,56)[0]
		self.modified_count_at_last_promotion 	= struct.unpack_from(str("<q"), self.buf,64)[0]
		self.next_rid				= struct.unpack_from(str("<I"), self.buf,72)[0]
		self.password_properties		= struct.unpack_from(str("<I"), self.buf,76)[0]
		self.min_password_length		= struct.unpack_from(str("<H"), self.buf,80)[0]
		self.password_history_length		= struct.unpack_from(str("<H"), self.buf,82)[0]
		self.lockout_threshold			= struct.unpack_from(str("<H"), self.buf,84)[0]
		self.unk2				= struct.unpack_from(str("<H"), self.buf,86)[0] # mimikatz wrong. -> https://github.com/inquisb/keimpx/blob/master/lib/structures.py
		self.domain_server_enable_state		= struct.unpack_from(str(">I"), self.buf,88)[0]
		self.domain_server_role			= struct.unpack_from(str("<I"), self.buf,92)[0]
		self.uas_compatibility_required		= struct.unpack_from(str("<I"), self.buf,96)[0]
		self.unk3				= struct.unpack_from(str("<I"), self.buf,100)[0]
		self.keys1				= SAM_KEY_DATA_AES(buf,104)
		self.unk4				= struct.unpack_from(str("<q"), self.buf,216)[0] # mine
		self.unk5				= struct.unpack_from(str("<q"), self.buf,224)[0] # mine
		self.keys2				= SAM_KEY_DATA_AES(buf,232)
		self.unk6				= struct.unpack_from(str("<q"), self.buf,344)[0] # mine
		self.unk7				= struct.unpack_from(str("<q"), self.buf,352)[0] # mine
		self.unk8				= struct.unpack_from(str("<q"), self.buf,360)[0] # mine
		print "key1 rev: ", self.keys1.revision
		print "key2 rev: ", self.keys2.revision

f_system_hive = open("system.hive","rb")
r_system_hive = Registry.Registry(f_system_hive)

f_sam_hive = open("sam.hive","rb")
r_sam_hive = Registry.Registry(f_sam_hive)

def get_current_control_set(registry):
	key = registry.open("Select")

	for value in key.values():
		if value.name() == "Current":
			return ("ControlSet%03d" % (value.value()))

def get_computer_name(registry, current_control_set):
	key = registry.open(current_control_set + "\\Control\\ComputerName\\ComputerName")

	for value in key.values():
		if value.name() == "ComputerName":
			return value.value()

def get_sys_key(registry, current_control_set):
	permut = [11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4]
	syskey = []
	buffer = registry.open(current_control_set + "\\Control\\Lsa\\JD").get_class().decode('hex')[::-1] # LE/BE endiannes.. [::-1]
	buffer += registry.open(current_control_set + "\\Control\\Lsa\\Skew1").get_class().decode('hex')[::-1]
	buffer += registry.open(current_control_set + "\\Control\\Lsa\\GBG").get_class().decode('hex')[::-1]
	buffer += registry.open(current_control_set + "\\Control\\Lsa\\Data").get_class().decode('hex')[::-1]
	#print "test: ", str(''.join(buffer))
	print "syskey before: ", (''.join(buffer)).encode('hex')
	for i in xrange(16):
		syskey.append(buffer[permut[i]])
	return (''.join(syskey))

def get_sid(registry):
	key = registry.open("SAM\\Domains\\Account")

	for value in key.values():
		if value.name() == "V":
			data = value.value()

	sid_raw = data[-24:]

	revision = ord(sid_raw[0])
	sub_authority_count = ord(sid_raw[1])
	identifier_authority = int(sid_raw[2:8].encode('hex'),16)
	dword1 = int(sid_raw[8:12][::-1].encode('hex'),16)
	dword2 = int(sid_raw[12:16][::-1].encode('hex'),16)
	dword3 = int(sid_raw[16:20][::-1].encode('hex'),16)
	dword4 = int(sid_raw[20:24][::-1].encode('hex'),16)

	return ("S-%d-%d-%d-%d-%d-%d" % (revision,identifier_authority,dword1,dword2,dword3,dword4))

def decrypt_aes(syskey, aes_iv, aes_data):
	obj = AES.new(syskey ,AES.MODE_CBC, aes_iv)
	msg = obj.decrypt(aes_data)
	return msg

def get_sam_key(registry, syskey):
	key = registry.open("SAM\\Domains\\Account")

	for value in key.values():
                if value.name() == "F":
                        data = value.value()

	account = DOMAIN_ACCOUNT_F(data)
	print "dom rev: ", account.revision
	print "enc sam key:", account.keys1.data[:account.keys1.data_len].encode('hex')
	decrypted_data = decrypt_aes(syskey, account.keys1.salt, account.keys1.data[:account.keys1.data_len])
	return decrypted_data[:16]

# source: http://www.insecurity.be/blog/2018/01/21/retrieving-ntlm-hashes-and-what-changed-technical-writeup/
def str_to_key(dessrc):
	bkey = binascii.unhexlify(dessrc)
	keyarr = []
	for i in range(0, len(bkey)): keyarr.append(int(binascii.hexlify(bkey[i]),16))
	bytearr = []
	bytearr.append(keyarr[0]>>1)
	bytearr.append(((keyarr[0] & 0x01) << 6) | keyarr[1] >> 2)
	bytearr.append(((keyarr[1] & 0x03) << 5) | keyarr[2] >> 3)
	bytearr.append(((keyarr[2] & 0x07) << 4) | keyarr[3] >> 4)
	bytearr.append(((keyarr[3] & 0x0F) << 3) | keyarr[4] >> 5)
	bytearr.append(((keyarr[4] & 0x1F) << 2) | keyarr[5] >> 6)
	bytearr.append(((keyarr[5] & 0x3F) << 1) | keyarr[6] >> 7)
	bytearr.append(keyarr[6]&0x7F)
	result = ''
	for b in bytearr:
		bit = bin(b*2)[2:].zfill(8)
		if bit.count('1') %2 == 0:
			result += hex((b * 2) ^ 1)[2:].zfill(2)
		else:
			result += hex(b * 2)[2:].zfill(2)
	return result

def decrypt_des(buffer, rid):
	# SystemFunction025(in, key, out) - decrypt 2 des blocks with 32bit key
	# LM -> isNTLM FALSE. isHistory FALSE -> "LM"
	# NTLM-> TRUE, FALSE -> "NTLM"
	# LMHist-> FALSE, TRUE -> "lm"
	#NTLMHist -> TRUE TRUE -> "ntlm"
	# rid used as number (DWORD) -> 0xf401 0000 -> [0,1,2,3,0,1,2] des1 = f4010000f40100 ; [3,0,1,2,3,0,1] des2 = 00f4 0100 00f4 01
	# cypheredHashBuffer.Buffer -> DES ciphered data
	s_rid = struct.pack("<I",rid)
	dessrc1 = s_rid + s_rid[:3]
	dessrc2 = s_rid[3] + s_rid[0] + s_rid[1] + s_rid[2] + s_rid[3] + s_rid[0] + s_rid[1]
	s_des1 = str_to_key(dessrc1.encode('hex'))
	s_des2 = str_to_key(dessrc2.encode('hex'))
	des1 = s_des1.decode('hex')
	des2 = s_des2.decode('hex')
	#m1 = buffer[:8], des1
	#m2 = buffer[8:], des2
	# m = m1 + m2
	obj1 = DES.new(des1)
	m1 = obj1.decrypt(buffer[:8])
	obj2 = DES.new(des2)
	m2 = obj2.decrypt(buffer[8:])
	m = m1+m2
	print "HASH: ", m.encode('hex')

def get_hash(registry, sk):
	key = registry.open("SAM\\Domains\\Account\\Users")
	key_names = registry.open("SAM\\Domains\\Account\\Users\\Names")

	for k in key_names.subkeys():
		user = k.values()[0].value_type()
		key_user = registry.open(("SAM\\Domains\\Account\\Users\\%08x" % (user)))
		acc = USER_ACCOUNT_V(key_user.values()[1].value(),0)
		l = acc.username.length
		o = acc.username.offset
		print acc.data[o:o + l]
		l = acc.lm_hash.length
		o = acc.lm_hash.offset
		h = SAM_HASH_AES(acc.data[o:o+l],0)
		print "aes rev: ", h.revision
		#print "o: ", o
		#print "l: ", l
		#print len(h.data)
		#print h.data_offset
		l = acc.ntlm_hash.length
                o = acc.ntlm_hash.offset
                h = SAM_HASH_AES(acc.data[o:o+l],0)
		print "aes rev: ", h.revision
		print "o: ", o
                print "l: ", l
		#print h.data_offset
		#print len(h.data)
		#sk, h.salt, h.data, l-24
		m = decrypt_aes(sk, h.salt,  h.data)[:16]
		print m.encode('hex')
		rid = user
		decrypt_des(m,rid)

print get_computer_name(r_system_hive, get_current_control_set(r_system_hive))
syskey = get_sys_key(r_system_hive,get_current_control_set(r_system_hive))
print "syskey: ", syskey.encode('hex')

print get_sid(r_sam_hive)
k = get_sam_key(r_sam_hive, syskey)
print "samkey: ", k.encode('hex')

print get_hash(r_sam_hive, k)
print str_to_key("f4010000f40100")
print str_to_key("00f4010000f401")
