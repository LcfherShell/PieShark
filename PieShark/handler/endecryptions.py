import requests, base64, hashlib, re, string, secrets, sys, math, time, random, os
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from Crypto import Random
from Crypto.Cipher import AES
from bs4 import BeautifulSoup
from chardet import detect
import statistics

PY3 = sys.version_info[0] == 3


if PY3:
	string_types = str
else:
	string_types = basestring

token_api = ''

cache_base128 = []
class Base64_Token_128:
	"""docstring for Base64_Token_128"""
	def __init__(self, app):
		super(Base64_Token_128, self).__init__()
		self.app = app
		try:
			if len(self.app.config['URI_TOKEN'])>5:
				self.remove_function = True
			else:
				self.remove_function = False
		except:
			self.remove_function = False
		self.cache = None
		self.cookies = None

	@property
	def Make_Key(self):
		key_mapp__ = [ random.randint(3, 9) for _ in range(0, 12)]
		self.cache = ''
		for _ in range(0, random.choice([statistics.mode(key_mapp__), round(statistics.median(key_mapp__))])):
			self.cache += "-".join([str(random.getrandbits(x)) for x in key_mapp__])
		def u_id(self, token):
			cache, token =  [self.cache, token]
			return sum( [ int(int_) for int_ in self.cache.split('-')] )/int(token)
		#u_id(self, token=12)
		self.cirt = u_id(self, token=self.mode( [ int(_output) for _output in self.cache.split('-')], 'nm' ) )
		self.cache = str(round(self.cirt)).encode('utf-8')

	@staticmethod
	def key_mapp__(self):
		key_mapp__ = {
		"data2": "as15",
		"data2_0": "as15",
		"data2_5": "as180",
		"data3":"abc152",
		"data3_0":"abc152",
		"data3_5":"acb180",
		"data4":"cbn992",
		"data4_0":"cbn992",
		"data4_5":"vbs999",
		"data5":"xvas1823",
		"data5_0":"xvas1823",
		"data5_5":"xvbs1938",
		"data6": "aks127cc",
		"data6_0": "aks127cc",
		"data6_5": "aks688cd",
		"data7":"zer0b726",
		"data7_0":"zer0b726",
		"data7_5":"zer0b99d",
		"data8":"n0xc627zo",
		"data8_0":"n0xc627zo",
		"data8_5":"n0xc6987v",
		"data9":"death9999xxx",
		"data9_0":"death9999xxx"
		}

		median = self.mode( [ _x_int_ for _x_int_ in range(2, 9) if int(self.cache.decode('utf-8'))%_x_int_] , 'mo')
		median_split = str(median).split(".")
		keyword = "data"+str([median if median_split[1:len(median_split)] != '0' else int(median)][0]).replace(".", "_")
		return key_mapp__[keyword] or key_mapp__.get(keyword)

	def mode(self, arr, funct):
		if funct == "mo":
			return statistics.median(arr)
		elif funct == "nm":
			return statistics.mode(arr)
		else:
			raise TypeError("------------")

	def decode_base64(self, key, message):
		dec = []
		if id(key) != id(self.key_mapp__(self)):
			raise TypeError("Failed Key") 

		padding = 4 - (len(message) % 4)
		message = message + ("=" * padding)
		message = base64.urlsafe_b64decode(message).decode('utf-8')
		message = message.split('-')
		for v in range(len(message)):
			key_c = key[v % len(key)]
			dec_c = chr((ord(message[v]) - ord(key_c)))
			dec.append(dec_c)
		if self.cookies:
			raise MemoryError("Please, delete existing cookies")
		else:
			self.cookies = "".join([str(random.getrandbits(ord(x))) for x in dec.copy()])
		return "".join(dec)

	def encode_base64(self, key, message):
		enc = []
		if id(key) != id(self.key_mapp__(self)):
			raise TypeError("Failed Key") 
		for n in range(len(message)):
			key_c = key[n % len(key)]
			en = chr(ord(message[n])+ord(key_c))
			enc.append(en)
		if self.cookies:
			raise MemoryError("Please, delete existing cookies")
		else:
			self.cookies = "".join([str(random.getrandbits(ord(x))) for x in enc.copy()])
		return base64.urlsafe_b64encode(str("-".join(enc)).encode('utf-8')).decode('utf-8').rstrip("=")

	@property
	def remove(self):
		print(cache_base128)

	@remove.setter
	def remove(self):
		raise TypeError("remove coordinate is read and delete")
		
	@remove.deleter
	def remove(self):
		global cache_base128
		def rm(self):
			if self.cookies and self.cache:
				self.cache = None
				self.cookies = None
			else:
				pass
		if self.remove_function:
			cache = self.cache
			rm(self)
			self.cache = cache
		else:
			rm(self)
		try:
			self.caches1 = bytes(self.cache.decode('utf-8'), 'utf-8')
			self.caches2 = bytes(self.cache.decode('utf-8'), 'ascii')
		except:
			self.caches1 = self.cache.decode('utf-8').encode('utf-8')
			self.caches2 = self.cache.decode('utf-8').encode('ascii')

		array_bytes1, array_bytes2 =[[], []]

		for byte in self.caches1:
			array_bytes1.append(byte)

		for byte in self.caches2:
			array_bytes2.append(byte)

		assert array_bytes1 == array_bytes2
		cache = list(set(array_bytes1))
		if len(cache_base128) == 0:
			cache_base128 = cache
		else:
			cache_base128.clear()

	



class Ciphertext_128:
            def __init__(self):
                self.get = {
                'upper': string.ascii_uppercase,
                'lower': string.ascii_lowercase ,
                'letther': string.ascii_letters ,
                'digits': string.digits,
                'speciall': string.punctuation
                }
                self.data = ''
                self.hex_logic = 0xaa, None
            def Generate_String(self, size):
                chars = self.get['letther']+str(self.get['digits'])+self.get['speciall']
                return ''.join(random.choice(chars) for _ in range(size))

            def ciphertext(self, options='encrypt', text="test"):
                mapkey = {'A': '9', 'B': 'O', 'C': '3', 'D': 'R', 'E': 'v', 'F': "'", 'G': ';', 'H': '(', 'I': '2', 'J': ',', 'K': 'm', 'L': 'w', 'M': 'g', 'N': '[', 'O': '"', 'P': '}', 'Q': 'q', 'R': '7', 'S': 'T', 'T': '1', 'U': 'K', 'V': ']', 'W': 'Y', 'X': 'b', 'Y': 'e', 'Z': 'l', 'a': 'u', 'b': 'H', 'c': 'V', 'd': '6', 'e': ':', 'f': '5', 'g': 'B', 'h': 'y', 'i': ' ', 'j': 'z', 'k': 'N', 'l': '<', 'm': 'F', 'n': '!', 'o': '0', 'p': '^', 'q': 'p', 'r': 'I', 's': '\\', 't': 'j', 'u': 'd', 'v': 'c', 'w': 'W', 'x': '>', 'y': 'Q', 'z': '/', '0': '~', '1': 'C', '2': '&', '3': '.', '4': '`', '5': '@', '6': 'D', '7': '$', '8': '=', '9': 'o', ':': 'E', '.': 'L', ';': '{', ',': '#', '?': 'S', '!': 's', '@': 't', '#': 'J', '$': '_', '%': '+', '&': 'k', '(': 'i', ')': '?', '+': 'a', '=': 'U', '-': '*', '*': '-', '/': 'M', '_': '%', '<': 'X', '>': 'A', ' ': 'G', '[': 'n', ']': 'f', '{': 'h', '}': 'x', '`': 'r', '~': 'Z', '^': 'P', '"': '8', "'": '4', '\\': ')'} , self.hex_logic
                self.chars = self.get['letther']+str(self.get['digits'])+self.get['speciall']
                public_key = ''
                private_key = ''
                def generate_key(self):
                   """Generate an key for our cipher"""
                   global mapkey
                   shuffled = sorted(self.chars, key=lambda k: random.random())
                   mapkey = dict(zip(self.chars, shuffled)), self.hex_logic
                   return mapkey
                def login_(self, mapx=2):
                    exract_key= int(mapkey[1:][0][:1][0])
                    if exract_key%mapx == 0:
                        private_key = exract_key is self.hex_logic[0]
                        public_key = mapkey[:1][0]
                        return private_key, public_key
                    return False, None
                    ########Encrypt text using chipherset 128bit
                def encrypt(key, plaintext):
                    """Encrypt the string and return the ciphertext"""
                    return ''.join(key[l] for l in plaintext)
                def decrypt(key, ciphertext):
                    """Decrypt the string and return the plaintext"""
                    flipped = {v: k for k, v in key.items()}
                    return ''.join(flipped[l] for l in ciphertext) 

                log = login_(self)
                pent0 = []
                pent1 = []
                if log[0] == True:
                    for data in log[1]:
                                pent0.append(data)
                                pent1.append(log[1][data])
                    key = dict(zip(pent0, pent1))

                if options == 'encrypt':
                    try:
                        return encrypt(key, text)
                    except:
                        return None
                elif options == 'decrypt':
                    try:
                        return decrypt(key, text)
                    except:
                        return None
                elif options == 'generate-key':
                    mapkey = generate_key(self)
                    return mapkey
                elif options == 'show-key':
                    try:
                        return key
                    except:
                        return None
                else:
                    return None

            def HexaDecimall(self, options='encrypt'):
                def Hex_to_Str(self):
                    hex = self.data.replace('-0x128', '')
                    if 0xaa in self.hex_logic and self.data[:2] == '0x':
                        hex = self.data[2:]
                    output = bytes.fromhex(hex).decode('utf-8')
                    return self.ciphertext(text=output, options='decrypt')

                def Str_to_hex(self):
                    if 0xaa in self.hex_logic:
                        self.data = self.ciphertext(text=self.data, options='encrypt')
                        output = f"{self.data}".encode('utf-8')
                        return str(output.hex()+'-0x128')
                    return None
                if options.lower()=='decrypt':
                    data = Hex_to_Str(self)
                    return data
                elif options.lower()=='encrypt':
                    data = Str_to_hex(self)
                    return data
                else:
                    return
class Magic_Data:
	"""docstring for Magic_Data"""
	def __init__(self, msg):
		super(Magic_Data, self).__init__()
		self.msg = msg
		self.token = ''
		self.create_token(127)

	def create_token(self, lenght):
		alphabet = string.ascii_letters + string.digits
		while True:
			self.token = ''.join(secrets.choice(alphabet) for i in range(lenght))
			if any(c.islower() for c in self.token) and any(c.isupper() for c in self.token) and any(c.isdigit() for c in self.token):
				break
		self.token = self.token

	def string_2_bin(self, msg=None):
		data_bin, binary_output = [[],[]]
		if msg != None:
			if len(msg) !=0:
				self.msg = msg

		for x in self.msg:
			data_bin.append(ord(x))

		for data_b in data_bin:
			binary_output.append(int(bin(data_b)[2:]))
		self.msg = binary_output
		self.load()
		return self.msg

	def bin_2_string(self, msg=None):
		logic_bin, output_str = [[], '']
		if msg != None:
			if len(msg) !=0:
				self.msg = msg
		self.load()
		for i in self.msg:
			i = int(i)
			b = 0
			c = 0
			k = int(math.log10(i))+1
			for j in range(k):
				b = ((i%10)*(2**j))
				i = i//10
				c = c+b
			logic_bin.append(c)
		for x in logic_bin:
			output_str = output_str+chr(x)
		return output_str

	def load(self):
		time.sleep(1.2)
		if self.msg and isinstance(self.msg, list):
			self.msg = "-".join(map(str, self.msg))
		elif self.msg and isinstance(self.msg, str):
			self.msg = self.msg.strip().split('-')
		return self.msg, 200

class AESCipher:

    def __init__(self, key): 
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

class AUTH_TOKEN:
	"""docstring for AUTH_TOKEN"""
	def __init__(self, app):
		super(AUTH_TOKEN, self).__init__()
		self.token = None
		self.point = 0
		self.cookiename = None
		try:
			self.algorith = app.config['AUTH_TOKEN']
		except:
			self.algorith = app

		if self.algorith.lower() != "md5":
			raise TypeError(f"No value ({self.algorith}) in dictionary")
	
	def create(self, lenght):
		global token_api
		alphabet = string.ascii_letters + string.digits
		while True:
			self.token = ''.join(secrets.choice(alphabet) for i in range(lenght))
			if any(c.islower() for c in self.token) and any(c.isupper() for c in self.token) and any(c.isdigit() for c in self.token):
				break
		self.token = self.token
		token_api = self.token
		return self.token

	def check(self, token):
		global token_api
		if isinstance(token, string_types):
			if token == self.token:
				token_api = None
				self.token = None
				return True
			elif token == token_api:
				token_api = None
				self.token = None
				return True
			else:
				if self.is_json(token):
					try:
						data = json.load(token)
					except:
						data = json.loads(token)

					for json_load in data:
						if data[json_load] == self.token:
							self.token = None
							token_api = None
							break
							return True
						elif data[json_load] == token_api:
							self.token = None
							token_api = None
							break
							return True
					return False
				else:
					try:
						token = token.cookies.get(self.cookiename)
						self.check(token)
					except:
						try:
							for x in re.findall(r'[\w\.-]+=', token):
								token = token.replace(x, "")
							data = token.split(";")
							if any(self.token in e for e in data):
								self.token = None
								token_api = None
								return True
							elif any(token_api in e for e in data):
								self.token = None
								token_api = None
								return True
							else:
								return False
						except TypeError:
							return False
		else:
			self.check(str(token))

	def is_json(self, data):
		try:
			json.loads(data)
		except:
			try:
				json.load(data)
				return True
			except:
				return False
		return True	

from Crypto.Util.Padding import unpad,pad

class AESCipher_2:
	"""docstring for AESCipher_2"""
	def __init__(self, secretKey, salt):
		super(AESCipher_2, self).__init__()
		self.private_key = self.get_private_key(secretKey, salt)

	def get_private_key(self, secretKey, salt):
		    # _prf = lambda p,s: HMAC.new(p, s, SHA256).digest()
		    # private_key = PBKDF2(secretKey, salt.encode(), dkLen=32,count=65536, prf=_prf )
		    # above code is equivalent but slow
		    key = hashlib.pbkdf2_hmac('SHA256', secretKey.encode(), salt.encode(), 65536, 32)
		    # KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, 256);
		    return key

	def encrypt(self, message):
	    message = pad(message.encode(), AES.block_size)
	    iv = "\x00"*AES.block_size  # 128-bit IV
	    cipher = AES.new(self.private_key, AES.MODE_CBC, iv.encode())
	    return base64.b64encode(cipher.encrypt(message))

	def decrypt(self, message):
	    enc = base64.b64decode(enc)
	    iv = "\x00"*AES.block_size
	    cipher = AES.new(self.private_key, AES.MODE_CBC, iv.encode())
	    return unpad(cipher.decrypt(message), AES.block_size).decode('utf-8')

def secreet_token(lenght):
	alphabet = string.ascii_letters + string.digits
	return ''.join([random.choice(alphabet) for _ in range(lenght)])
