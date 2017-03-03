// Mun Hao Ran
// J14014976 / 4809920

/* Operation.h */
#include "../CryptoPP/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::SecByteBlock;
using CryptoPP::OS_GenerateRandomBlock;

#include "../CryptoPP/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "../CryptoPP/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::HashFilter;
using CryptoPP::SHA1;

#include "../CryptoPP/integer.h"
using CryptoPP::Integer;

#include "../CryptoPP/rsa.h"
using CryptoPP::RSA;

#include "../CryptoPP/des.h"
using CryptoPP::DES_EDE2;

#include "../CryptoPP/modes.h"
using CryptoPP::ECB_Mode;

using namespace std;

// KeyPair structure
struct KeyPair
{
	string publicKey;
	string privateKey;
};

// Function prototypes
KeyPair generateKeys(AutoSeededRandomPool &);
string createHash(string);
bool verifyPublicKeys(char *);
string createSessionKey();
string encryptSessionKey(string, char []);
string decryptSessionKey(string, AutoSeededRandomPool &, KeyPair);
bool verifySessionKeys(string, string);
string encryptMessage(const string &, const string &);
string decryptMessage(const string &, const string &);

