/*
===============================================================================================
Author  : Mun Hao Ran
Date    : 20-6-2016
Purpose : C++ RSA-3DES handshake and data communication program using crypto++ library.
===============================================================================================
*/

/* Main */
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <sstream>
#include "Operation.h"

// Link to Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_PORT "8080"

// Main
int main(int argc, char* argv[])
{
	// Validate parameters
	if (argc != 2)
	{
		cout << "Usage : Station [A/B]" << endl;
		return 1;
	}

	string station = argv[1];

	// Station A (Client)
	if (station == "A")
	{
		WSADATA wsaData;
		SOCKET ConnectSocket = INVALID_SOCKET;
		struct addrinfo *result = NULL, *ptr = NULL, hints;
		string IP, port;
		int rv;

		// Initialize Winsock
		rv = WSAStartup(MAKEWORD(2, 2), &wsaData);

		if (rv != 0)
		{
			cout << "Error! Failed to startup WSA . . ." << endl;
			return 1;
		}

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		cout << "--------------------------------------------------------------------------------" << endl;
		cout << "Station A (Client)" << endl;
		cout << "--------------------------------------------------------------------------------" << endl;

		cout << "IP Address : ";
		cin >> IP;

		cout << "Port\t   : ";
		cin >> port;

		// Resolve server address and port
		rv = getaddrinfo(IP.c_str(), port.c_str(), &hints, &result);

		if (rv != 0)
		{
			cout << "Error! Failed to get address information . . ." << endl;
			WSACleanup();
			return 1;
		}

		// Continue to connect to an address until one succeeds
		for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
		{
			// Create socket
			ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

			if (ConnectSocket == INVALID_SOCKET)
			{
				cout << "Error! Failed to create socket . . ." << endl;
				WSACleanup();
				return 1;
			}

			// Connect to server
			rv = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);

			if (rv == SOCKET_ERROR)
			{
				closesocket(ConnectSocket);
				ConnectSocket = INVALID_SOCKET;
				continue;
			}

			break;
		}

		freeaddrinfo(result);

		if (ConnectSocket == INVALID_SOCKET)
		{
			cout << "Error! Unable to connect to server!" << endl;
			WSACleanup();
			return 1;
		}
		else
		{
			cout << "Connected to Station B (Server) successfully!" << endl;
			cout << "--------------------------------------------------------------------------------" << endl;
		}

		/* ----------------- */
		/* Handshake process */
		/* ----------------- */

		cout << "Generating private and public key . . ." << endl;

		// Pseudo random number generator
		AutoSeededRandomPool rng;

		// Generate private and public keys
		KeyPair keys = generateKeys(rng);

		cout << "Creating hash of public key . . ." << endl;

		// Create hash of public key using SHA1
		string hashPubKey = createHash(keys.publicKey);

		string sendPubKeys;
		stringstream ss;

		// Store public key and hash of public key to stringstream
		ss << keys.publicKey << " " << hashPubKey;
		sendPubKeys = ss.str();

		cout << "Sending public key and hash of public key to Station B . . ." << endl;

		// Send public and hash of public key to server
		rv = send(ConnectSocket, sendPubKeys.c_str(), strlen(sendPubKeys.c_str()), 0);

		if (rv == SOCKET_ERROR)
		{
			cout << "Error! Failed to send data to server . . ." << endl;
			closesocket(ConnectSocket);
			WSACleanup();
			return 1;
		}

		char recvSessionKeys[2048];
		bool verify = false;

		cout << "--------------------------------------------------------------------------------" << endl;
		cout << "Receiving encrypted session key and hash of session key from Station A . . ." << endl;

		// Receive session key and hash of session key from server
		rv = recv(ConnectSocket, recvSessionKeys, 2048, 0);

		if (rv > 0)
		{
			recvSessionKeys[rv] = '\0';

			string eSessionKey = strtok(recvSessionKeys, " ");
			string hashSessionKey = strtok(NULL, " ");	
				
			// Decrypt session key
			string sessionKey = decryptSessionKey(eSessionKey, rng, keys);

			cout << "\nEncrypted session key" << endl;
			cout << "---------------------" << endl;
			cout << eSessionKey << endl;
			cout << "\nHash of session key" << endl;
			cout << "---------------------" << endl;
			cout << hashSessionKey << endl;
			cout << "\nDecrypted session key" << endl;
			cout << "---------------------" << endl;
			cout << sessionKey << endl;

			cout << "--------------------------------------------------------------------------------" << endl;

			string status;

			// Verify session key
			verify = verifySessionKeys(hashSessionKey, sessionKey);

			if (verify)
			{
				status = "Verified";

				cout << "Handshake process completed!" << endl;
				cout << "Both stations are now ready to use '" << sessionKey << "' for communication . . ." << endl;
			}
			else
			{
				status = "Not verified";
			}

			cout << "--------------------------------------------------------------------------------" << endl;

			// Send verification status to server
			rv = send(ConnectSocket, status.c_str(), strlen(status.c_str()), 0);

			if (rv == SOCKET_ERROR)
			{
				cout << "Error! Failed to send data to server . . ." << endl;
				closesocket(ConnectSocket);
				WSACleanup();
				return 1;
			}

			// Terminates if session key is not verified
			if (status == "Not verified")
			{
				return 1;
			}

			string message;
			string ciphertext;

			cin.ignore();

			/* -------------------------- */
			/* Data communication process */
			/* -------------------------- */

			// Continue to send message and receive reply
			do
			{
				cout << "Message   : ";
				getline(cin, message);

				// Encrypt message
				ciphertext = encryptMessage(message, sessionKey);

				cout << "Encrypted : " << ciphertext << endl;

				// Send ciphertext to server
				rv = send(ConnectSocket, ciphertext.c_str(), strlen(ciphertext.c_str()), 0);

				if (rv == SOCKET_ERROR)
				{
					cout << "Error! Failed to send data to server . . ." << endl;
					closesocket(ConnectSocket);
					WSACleanup();
					return 1;
				}

				char reply[2048];

				// Receive reply from server
				rv = recv(ConnectSocket, reply, 2048, 0);

				if (rv == SOCKET_ERROR)
				{
					cout << "Error! Failed to send data to client . . ." << endl;
					closesocket(ConnectSocket);
					WSACleanup();
					return 1;
				}

				reply[rv] = '\0';

				cout << "\nReply     : " << reply << endl;

				// Decrypt reply
				message = decryptMessage(reply, sessionKey);

				cout << "Decyrpted : " << message << endl;

				cin.clear();
				cout << endl;

			} while (rv > 0);
		}
		else if (rv == 0)
		{
			cout << "Connection closed . . ." << endl;
		}
		else
		{
			cout << "Error! Failed to receive data from server . . ." << endl;
		}

		// Shutdown connection
		rv = shutdown(ConnectSocket, SD_SEND);

		// Cleanup
		closesocket(ConnectSocket);
		WSACleanup();
	}
	// Station B (Server)
	if (station == "B")
	{
		WSADATA wsaData;
		int rv;

		SOCKET ListenSocket = INVALID_SOCKET;
		SOCKET ClientSocket = INVALID_SOCKET;

		struct addrinfo *result = NULL;
		struct addrinfo hints;

		// Initialize Winsock
		rv = WSAStartup(MAKEWORD(2, 2), &wsaData);

		if (rv != 0)
		{
			cout << "Error! Failed to startup WSA . . ." << endl;
			return 1;
		}

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;

		cout << "--------------------------------------------------------------------------------" << endl;
		cout << "Station B (Server)" << endl;
		cout << "--------------------------------------------------------------------------------" << endl;

		// Resolve server address and port
		rv = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);

		if (rv != 0)
		{
			cout << "Error! Failed to get address information . . ." << endl;
			WSACleanup();
			return 1;
		}

		// Create server socket
		ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

		if (ListenSocket == INVALID_SOCKET)
		{
			cout << "Error! Failed to create socket . . ." << endl;
			freeaddrinfo(result);
			WSACleanup();
			return 1;
		}

		// Setup TCP/IP listening socket
		rv = ::bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);

		if (rv == SOCKET_ERROR)
		{
			cout << "Error! Failed to bind socket . . ." << endl;
			freeaddrinfo(result);
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}

		freeaddrinfo(result);

		rv = listen(ListenSocket, SOMAXCONN);

		if (rv == SOCKET_ERROR)
		{
			cout << "Error! Failed to listen socket . . ." << endl;
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}
		else
		{
			cout << "Server is alive and waiting for client to connect . . ." << endl;
		}

		// Accept client socket
		ClientSocket = accept(ListenSocket, NULL, NULL);

		if (ClientSocket == INVALID_SOCKET)
		{
			cout << "Error! Failed to accept client socket . . ." << endl;
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}
		else
		{
			cout << "Station A (Client) is connected successfully!" << endl;
			cout << "--------------------------------------------------------------------------------" << endl;
		}

		// Close server socket
		closesocket(ListenSocket);

		/* ----------------- */
		/* Handshake process */
		/* ----------------- */

		char recvPubKeys[2048];
		string sessionKey;
		bool verify = false;

		// Receive public and hash of public key from client
		rv = recv(ClientSocket, recvPubKeys, 2048, 0);

		if (rv > 0)
		{
			recvPubKeys[rv] = '\0';

			// Verify public key
			verify = verifyPublicKeys(recvPubKeys);

			// If public key is verified
			if (verify)
			{
				cout << "Generating session key . . ." << endl;

				// Create session key
				sessionKey = createSessionKey();

				cout << "Encrypting session key . . ." << endl;

				// Encrypt session key
				string eSessionKey = encryptSessionKey(sessionKey, recvPubKeys);

				cout << "Creating hash of session key . . ." << endl;

				// Create hash of session key using SHA1
				string hashSessionKey = createHash(sessionKey);

				cout << "--------------------------------------------------------------------------------" << endl;

				cout << "Session key" << endl;
				cout << "---------------------" << endl;
				cout << sessionKey << endl;
				cout << "\nEncrypted session key" << endl;
				cout << "---------------------" << endl;
				cout << eSessionKey << endl;
				cout << "\nHash of session key" << endl;
				cout << "---------------------" << endl;
				cout << hashSessionKey << endl;

				string sendSessionKeys;
				stringstream ss;

				// Store encrypted session key and hash of session key to stringstream
				ss << eSessionKey << " " << hashSessionKey;
				sendSessionKeys = ss.str();

				cout << "\nSending encrypted session key and hash of session key to Station B . . ." << endl;

				// Send encrypted session key and hash of session key to client
				rv = send(ClientSocket, sendSessionKeys.c_str(), strlen(sendSessionKeys.c_str()), 0);

				if (rv == SOCKET_ERROR)
				{
					cout << "Error! Failed to send data to client . . ." << endl;
					closesocket(ClientSocket);
					WSACleanup();
					return 1;
				}

				cout << "--------------------------------------------------------------------------------" << endl;

				char status[100];

				// Receive verification status from client
				rv = recv(ClientSocket, status, 100, 0);

				if (rv == SOCKET_ERROR)
				{
					cout << "Error! Failed to send data to client . . ." << endl;
					closesocket(ClientSocket);
					WSACleanup();
					return 1;
				}

				status[rv] = '\0';

				// Terminates if session key is not verified
				if (strcmp(status, "Verified") == 0)
				{
					cout << "Session key is verified!" << endl;
					cout << "Handshake process completed!" << endl;
					cout << "Both stations are now ready to use '" << sessionKey << "' for communication . . ." << endl;
					cout << "--------------------------------------------------------------------------------" << endl;
				}
				else
				{
					cout << "Session key is not verified!" << endl;
					cout << "Sorry! Handshake process is failed . . ." << endl;
					cout << "--------------------------------------------------------------------------------" << endl;
					return 1;
				}
			}
			else
			{
				cout << "--------------------------------------------------------------------------------" << endl;
				return 1;
			}

			string message;
			string ciphertext;

			/* -------------------------- */
			/* Data communication process */
			/* -------------------------- */

			// Continue to send message and decrypt reply
			do
			{
				char reply[2048];

				// Receive reply from client
				rv = recv(ClientSocket, reply, 2048, 0);

				if (rv == SOCKET_ERROR)
				{
					cout << "Error! Failed to send data to client . . ." << endl;
					closesocket(ClientSocket);
					WSACleanup();
					return 1;
				}

				reply[rv] = '\0';

				cout << "Reply     : " << reply << endl;

				// Decrypt reply
				message = decryptMessage(reply, sessionKey);

				cout << "Decyrpted : " << message << endl;

				cout << "\nMessage   : ";
				getline(cin, message);

				// Encrypt message
				ciphertext = encryptMessage(message, sessionKey);

				cout << "Encrypted : " << ciphertext << endl;

				// Send ciphertext to client
				rv = send(ClientSocket, ciphertext.c_str(), strlen(ciphertext.c_str()), 0);

				if (rv == SOCKET_ERROR)
				{
					cout << "Error! Failed to send data to server . . ." << endl;
					closesocket(ClientSocket);
					WSACleanup();
					return 1;
				}

				cin.clear();
				cout << endl;

			} while (rv > 0);
		}
		else if (rv == 0)
		{
			cout << "Connection closing . . ." << endl;
		}
		else
		{
			cout << "Error! Failed to receive data from client . . ." << endl;
			closesocket(ClientSocket);
			WSACleanup();
			return 1;
		}

		// Shutdown connection
		rv = shutdown(ClientSocket, SD_SEND);

		if (rv == SOCKET_ERROR)
		{
			cout << "Error! Shutdown failed . . ." << endl;
			closesocket(ClientSocket);
			WSACleanup();
			return 1;
		}

		// Cleanup
		closesocket(ClientSocket);
		WSACleanup();
	}

	return 0;
}