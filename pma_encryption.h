#include <sstream>
#include <windows.h>
#include "sha512.h"

using namespace std;

/********************************************************************

 Plus-Minus Algorithm (PMA) for ASCII Text Encryption

  V 1.0.0
 ********************************************************************

 * * * * * * * * * * * * * * *
 Author: Brenden Dane
 Email: brdane@gmail.com
 Published: 00/00/0000
 * * * * * * * * * * * * * * *

 This encryption algorithm is used to encrypt ASCII and UTF-8 data. A message
 is typed that the user wishes to encrypt, he/she provides a key, either
 in a typed fashion or using a file's contents, and the outcome is a gibberish-looking 
 string of text. Embedded in the encrypted text is a SHA256 hash of the encryption key
 to check if decrypting was, or was not, successful.


 This version of PMA only supports ASCII and UTF-8 data. This allows you to use certain
 types of files to use an an encryption key... for example, you can encrypt something
 with an OBJ file, which is a 3D-model format.
 
 Future development plans include support for UTF-16 and UTF-32, and all endian data.
 This will allow you to encrypt with essentially any file.


*/


//Adds two numbers, if the number gets above high_limit, it will wrap-around to low_limit and continue.
inline byte wraparound(byte n1, byte n2)
{
	for (byte i=0; i<n2; i++)
		if (n1 == 255)
			n1 = 1;
		else
			n1++;

	return n1;
}
    

//Subtracts one number from another, if the number gets below low_limit, it will wrap-around to high_limit and continue.
inline byte subtract_wraparound(byte n1, byte n2)
{
	for (byte i=0; i<n2; i++)
		if (n1 == 1)
			n1 = 255;
		else
			n1--;

	return n1;
}

string GenerateRandomKey(int count)
{
	string final;

	for (int i = 0; i < count; i++)
		final += char(1 + rand() % 255);

	return final;
}

inline bool contains(string in, string con)
{
	return (in.substr(0, con.size()) == con);
}


//Put in a string, put in what text/phrase/word/etc you want to replace, put in what you want to replace it with.
//Returns the string with replacements made, if there were any... if not, then you'll get an unchanged string.
inline string ReplaceAll(string str, const string from, const string to)
{
    size_t start_pos = 0;

    while((start_pos = str.find(from, start_pos)) != string::npos)
	{
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}


//Encrypt a string with PMA. first parameter is your message, second is your key to encrypt with.
inline string encrypt(string in, string key)
{
	if (in == "")
		return "<Cannot encrypt message if there is no message.>";
	if (key == "")
		return "<Missing an encryption key>";

	//Replace all breaks with special code, for bug-related reason.
	key = ReplaceAll(key, "\r\n", "<--PMAENCRYPT---037548-->");
	in = ReplaceAll(sha512(key) + in, "\r\n", "<--PMAENCRYPT---037548-->");

	//Take each character of our key...
	for (int input_char = 0; input_char < in.length(); input_char++)
	{
		//Take each character of our message...
		for (int key_char = 0; key_char < key.length(); key_char++)
		{
			int digest = key[key_char];

			//See if each character is at an odd or even index in the message...
			if ((key_char + input_char) % 2 == 0)//If we are at an even index, we will add the ascii value of the current key char we are at to the current message char's ascii value that we are at.
				in[input_char] = wraparound(in[input_char], digest);
		else
				in[input_char] = subtract_wraparound(in[input_char], digest); //If we are at an odd index, we will subtract the ascii value of the current key char we are at from the current message char's ascii value that we are at.
			//The add and subtract operations are using what I call, 'Wraparound Math' See these declarations in pma_encryption.h for more information.
		}
	}
	//Return our encrypted message.
	return in;
}


//Decrypt a PMA-encrypted message with a key. Same thing as encrypt(), but in reverse.                                            
inline string decrypt(string in, string key, bool bShowIfFail=false)
{
	if (in == "")
		return "<Cannot encrypt message if there is no message.>";
	if (key == "")
		return "<Missing an encryption key>";

	string confirm = sha512(key);

	//Replace line breaks due to a bug.
	key = ReplaceAll(key, "\r\n", "<--PMAENCRYPT---037548-->");

	//Perform decryption.
	for (int key_char = key.length() - 1; key_char > -1; key_char--)
	{
		for (int input_char = in.length() - 1; input_char > -1; input_char--)
		{
			int digest = key[key_char];

			if ((key_char + input_char) % 2 == 0)
				in[input_char] = subtract_wraparound(in[input_char], digest);
			else
				in[input_char] = wraparound(in[input_char], digest);
		}
	}

	//After the decryption attempt, this is when we look for our confirm word at the beginning of the message.
	//If it's there, then obviously the attempt was successful.
	if ( (!bShowIfFail) && (confirm != sha512(key)))
		return "<Decryption Un-successful>";
	
	//Remove the first 128 characters, which is the SHA512 hash.
	in = in.substr(128, in.length() - 1);
	in = ReplaceAll(in.data(), "<--PMAENCRYPT---037548-->", "\r\n");

	return in.data();
}
