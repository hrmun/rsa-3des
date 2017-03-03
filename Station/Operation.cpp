// Mun Hao Ran
// J14014976 / 4809920

/* Operation.cpp */
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <sstream>
#include "Operation.h"

// Generate public and private key
KeyPair generateKeys(AutoSeededRandomPool & rng)
{
	KeyPair keys;

	// Generate keys
	RSA::PrivateKey privateKey;

	privateKey.GenerateRandomWithKeySize(rng, 2048);

	RSA::PublicKey publicKey(privateKey);

	// Save keys
	publicKey.Save(HexEncoder(new StringSink(keys.publicKey)).Ref());
	privateKey.Save(HexEncoder(new StringSink(keys.privateKey)).Ref());

	return keys;
}

// Create hash value using SHA1
string createHash(string str)
{
	string result;

	SHA1 hash;
	StringSource(str, true, new HashFilter(hash, new HexEncoder(new StringSink(result))));

	return result;
}

// Verify public key
bool verifyPublicKeys(char* str)
{
	string publicKey;
	string hashPubKey;

	publicKey = strtok(str, " ");
	hashPubKey = strtok(NULL, " ");

	// Create hash of received public key using SHA1
	string tempHash = createHash(publicKey);

	// Compare both hash of public keys
	if (tempHash.compare(hashPubKey) == 0)
	{
		cout << "Public key is verified!" << endl;
		return true;
	}
	else
	{
		cout << "Public key is not verified!" << endl;
		return false;
	}
}

// Create session key
string createSessionKey()
{
	// Pseudo random number generator
	AutoSeededRandomPool prng;

	// Generate random key based on 2-key TripleDES key length
	SecByteBlock key(0x00, DES_EDE2::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	stringstream ss;
	string result;

	ss << key;
	result = ss.str();

	return result;
}

// Encrypt session key using public key
string encryptSessionKey(string sessionKey, char recvPubKeys[])
{
	RSA::PublicKey publicKey;

	string temp(recvPubKeys);

	// Load public key
	publicKey.Load(StringSource(temp, true, new CryptoPP::HexDecoder()).Ref());

	Integer m, c;

	m = Integer((const byte *)sessionKey.data(), sessionKey.size());

	// Encrypt message (session key)
	c = publicKey.ApplyFunction(m);

	stringstream ss;
	string result;

	ss << c;
	result = ss.str();

	return result;
}

// Decrypt session key using private key
string decryptSessionKey(string eSessionKey, AutoSeededRandomPool & rng, KeyPair keys)
{
	RSA::PrivateKey privateKey;
	RSA::PublicKey publicKey;

	// Load private and public key
	privateKey.Load(StringSource(keys.privateKey, true, new HexDecoder()).Ref());
	publicKey.Load(StringSource(keys.publicKey, true, new HexDecoder()).Ref());

	stringstream ss;
	ss << eSessionKey;

	Integer c;
	ss >> c;

	// Decrypt message (session key)
	Integer r = privateKey.CalculateInverse(rng, c);
	string result;

	size_t req = r.MinEncodedSize();
	result.resize(req);

	r.Encode((byte *)result.data(), result.size());

	return result;
}

// Verify session key
bool verifySessionKeys(string hashSessionKey, string sessionKey)
{
	// Create hash of received session key using SHA1
	string tempHash = createHash(sessionKey);

	// Compare both hash of session keys
	if (tempHash.compare(hashSessionKey) == 0)
	{
		cout << "Session key is verified!" << endl;
		return true;
	}
	else
	{
		cout << "Session key is not verified!" << endl;
		cout << "Sorry! Handshake process is failed . . ." << endl;
		return false;
	}
}

// Encrypt message
string encryptMessage(const string & plaintext, const string & key)
{
	string ciphertext;
	string encoded;

	SecByteBlock k((const byte*)key.data(), key.size());

	// Convert key string into SecByteBlock
	if (k.size() < DES_EDE2::KEYLENGTH)
	{
		k.CleanGrow(DES_EDE2::KEYLENGTH);
	}
	else
	{
		k.resize(DES_EDE2::KEYLENGTH);
	}

	ECB_Mode<DES_EDE2>::Encryption encryptor;
	encryptor.SetKey(k, k.size());

	// Encrypt message using ECB mode of 2-key TripleDES algorithm
	StringSource ssEncryptor(plaintext, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));

	// Encode ciphertext after encryption
	StringSource ssEncoder(ciphertext, true, new HexEncoder(new StringSink(encoded))); 

	return encoded;
}

// Decrypt message
string decryptMessage(const string & ciphertext, const string & key)
{
	string recoveredtext;
	string decoded;

	SecByteBlock k((const byte*)key.data(), key.size());

	// Convert key string into SecByteBlock
	if (k.size() < DES_EDE2::KEYLENGTH)
	{
		k.CleanGrow(DES_EDE2::KEYLENGTH);
	}
	else
	{
		k.resize(DES_EDE2::KEYLENGTH);
	}

	ECB_Mode<DES_EDE2>::Decryption decryptor;
	decryptor.SetKey(k, k.size());

	// Decode ciphertext before decryption
	StringSource ssDecoder(ciphertext, true, new HexDecoder(new StringSink(decoded)));

	// Decrypt message using ECB mode of 2-key TripleDES algorithm
	StringSource ssDecryptor(decoded, true, new StreamTransformationFilter(decryptor, new StringSink(recoveredtext))); 

	return recoveredtext;
}
