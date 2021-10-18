# Import required modules
import argparse
import hashlib

# Create the argument Parser
parser = argparse.ArgumentParser(description="File integrity checking with two modes. Mode A compares File hash with provided hash. Mode B compares two files' hashes.")
parser.add_argument('-m', '--mode', help='-m MODE (A: file and hash) (B: Compare two files)')
parser.add_argument('-f', '--file1', help='f File to Check hash or 1st File to compare (Depending on the mode)')
parser.add_argument('-g', '--file2', help='2nd file to compare (Only if mode B is selected)')
parser.add_argument('-s', '--hash_string', help='HASH (If mode A is selected)')

args = parser.parse_args()

# Map the arguments to its variables
mode = args.mode
mode = mode.upper()
file1 = args.file1
file2 = args.file2
hash_string = args.hash_string

#Colors, to make a pretty layout
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white

# Define functions that will be used to calculate hashes for files
def md5(file_to_hash):
    md5_hash = hashlib.md5()
    with open(file_to_hash, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def sha1(file_to_hash):
    sha1_hash = hashlib.sha1()
    with open(file_to_hash, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha1_hash.update(chunk)
    return sha1_hash.hexdigest()

def sha256(file_to_hash):
    sha256_hash = hashlib.sha256()
    with open(file_to_hash, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def sha512(file_to_hash):
    sha512_hash = hashlib.sha512()
    with open(file_to_hash, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha512_hash.update(chunk)
    return sha512_hash.hexdigest()

# Make a pretty layout to start the script and show selected options
print(Y + """
  _               _      _____                                          
 | |             | |    / ____|                                         
 | |__   __ _ ___| |__ | |     ___  _ __ ___  _ __   __ _ _ __ ___ _ __ 
 | '_ \ / _` / __| '_ \| |    / _ \| '_ ` _ \| '_ \ / _` | '__/ _ \ '__|
 | | | | (_| \__ \ | | | |___| (_) | | | | | | |_) | (_| | | |  __/ |   
 |_| |_|\__,_|___/_| |_|\_____\___/|_| |_| |_| .__/ \__,_|_|  \___|_|   
                                             | |                        
                                             |_|   	""")
print("%sBy MEGANUKE\n" % (W))

print("----------------------------------------------------------------")
print(B + "[-] MODE: " + W + mode)
print(B + "[-] File to Check: " + W + file1)
if mode == 'A':
	hash_lenght = len(hash_string)
	print(B + "[-] HASH: " + W + hash_string)
	if hash_lenght == 32:
		print(B + "[-] HASH Type:" + W + " MD5")
	elif hash_lenght == 40:
		print(B + "[-] HASH Type:" + W + " SHA1")
	elif hash_lenght == 64:
		print(B + "[-] HASH Type:" + W + " sha256")
	elif hash_lenght == 128:
		print(B + "[-] HASH Type:" + W + " sha512")
if mode == 'B':
	print(B + "[-] File to compare with: " + W + file2)
print("----------------------------------------------------------------\n")

# If mode A is selected, follow this Path.
if mode == 'A':
	# MD5 Hash comparison
	if hash_lenght == 32:
		print(Y + 'MD5 Hash comparison' + W)
		file_hash = md5(file1)
		print(file_hash)
		print(hash_string)
		if str(file_hash) == hash_string:
			print(Y + "Everything looks normal" + W)
		else:
			print(Y + "Something Smells Fishy!!" + W)

	# SHA1 Hash comparison
	if hash_lenght == 40:
		print(Y + 'SHA1 Hash comparison' + W)
		file_hash = sha1(file1)
		print(file_hash)
		print(hash_string)
		if str(file_hash) == hash_string:
			print(Y + "Everything looks normal" + W)
		else:
			print(Y + "Something Smells Fishy!!" + W)

	# SHA256 Hash comparison
	if hash_lenght == 64:
		print(Y + 'SHA256 Hash comparison' + W)
		file_hash = sha256(file1)
		print(file_hash)
		print(hash_string)
		if str(file_hash) == hash_string:
			print(Y + "Everything looks normal" + W)
		else:
			print(Y + "Something Smells Fishy!!" + W)

	# SHA512 Hash comparison
	if hash_lenght == 128:
		print(Y + 'SHA512 Hash comparison' + W)
		file_hash = sha512(file1)
		print(file_hash)
		print(hash_string)
		if str(file_hash) == hash_string:
			print(Y + "Everything looks normal" + W)
		else:
			print(Y + "Something Smells Fishy!!" + W)

if mode == 'B':

	# MD5 Hash comparison
	print(Y + 'MD5 Hash comparison' + W)
	file1_hash = md5(file1)
	file2_hash = md5(file2)
	print(file1_hash)
	print(file2_hash)
	if file1_hash == file2_hash:
		print(Y + "Everything looks normal\n" + W)
	else:
		print(Y + "Something Smells Fishy!!\n" + W)

	# SHA1 Hash comparison
	print(Y + 'SHA1 Hash comparison' + W)
	file1_hash = sha1(file1)
	file2_hash = sha1(file2)
	print(file1_hash)
	print(file2_hash)
	if file1_hash == file2_hash:
		print(Y + "Everything looks normal\n" + W)
	else:
		print(Y + "Something Smells Fishy!!\n" + W)

	# SHA256 Hash comparison
	print(Y + 'SHA256 Hash comparison' + W)
	file1_hash = sha256(file1)
	file2_hash = sha256(file2)
	print(file1_hash)
	print(file2_hash)
	if file1_hash == file2_hash:
		print(Y + "Everything looks normal\n" + W)
	else:
		print(Y + "Something Smells Fishy!!\n" + W)

	# SHA512 Hash comparison
	print(Y + 'SHA512 Hash comparison' + W)
	file1_hash = sha512(file1)
	file2_hash = sha512(file2)
	print(file1_hash)
	print(file2_hash)
	if file1_hash == file2_hash:
		print(Y + "Everything looks normal\n" + W)
	else:
		print(Y + "Something Smells Fishy!!" + W)
