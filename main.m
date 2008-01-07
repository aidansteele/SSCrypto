#import <Foundation/Foundation.h>
#import "SSCrypto.h"

int main (int argc, const char * argv[])
{
    NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];

	SSCrypto *crypto;
	int n;
	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	// TEST 1: Get SHA1 digest for string
	
	// This is the same as running the following command in the terminal:
	// echo -n "foo" | openssl dgst -sha1
	
	NSString *name = @"foo";
	
	crypto = [[SSCrypto alloc] init];
	[crypto setClearTextWithString:name];
	
	NSLog(@"Name: %@", [crypto clearTextAsString]);
	NSLog(@"SHA1 Digest of Name using digest method: %@", [[crypto digest:@"SHA1"] hexval]);
	
	NSData *sha1Name = [SSCrypto getSHA1ForData:[name dataUsingEncoding:NSUTF8StringEncoding]];
	NSLog(@"SHA1 Digest using getSHA1ForData method: %@", [sha1Name hexval]);
	
	NSLog(@" ");
	NSLog(@" ");
	NSLog(@" ");
	
    [crypto release];

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	// Test 2: Symmetric encryption and decryption using various ciphers
	
	NSData *seedData1 = [SSCrypto getKeyDataWithLength:32];
	crypto = [[SSCrypto alloc] initWithSymmetricKey:seedData1];
	
	NSArray *ciphers = [NSArray arrayWithObjects:@"aes256", @"aes128", @"blowfish", @"aes192",
		@"RC4", @"blowfish", @"RC5", @"des3", @"des", nil];
	
	NSString *password = @"pumpkin";
	[crypto setClearTextWithString:password];
	
	for(n = 0; n < [ciphers count]; n++)
	{
		NSData *cipherText = [crypto encrypt:[ciphers objectAtIndex:n]];
		NSData *clearText = [crypto decrypt:[ciphers objectAtIndex:n]];
		
		NSLog(@"Original password: %@", password);
		NSLog(@"Cipher text: '%@' using %@", [cipherText encodeBase64WithNewlines:NO], [ciphers objectAtIndex:n]);
		NSLog(@"Clear text: '%s' using %@", [clearText bytes], [ciphers objectAtIndex:n]);
		
		NSLog(@" ");
	}
	
	NSLog(@" ");
	NSLog(@" ");
	
	[crypto release];
	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	// Test 3: Generating digests from strings
	
	// This is the same as running the following command in the terminal:
	// echo -n "I like cheese" | openssl dgst -md5
	//
	// Where -md5 is the digest to use.
	// See man dgst for a list of all available digests.
	
	NSData *seedData2 = [SSCrypto getKeyDataWithLength:32];
	crypto = [[SSCrypto alloc] initWithSymmetricKey:seedData2];
	
	NSArray *digests = [NSArray arrayWithObjects:@"MD2", @"MD4", @"MD5", @"SHA1", @"RIPEMD160", nil];
	
	NSString *secret = @"I like cheese";
    [crypto setClearTextWithString:secret];
	
	for(n = 0; n < [digests count]; n++)
	{
		NSData *digest = [crypto digest:[digests objectAtIndex:n]];
		NSLog(@"'%@' %@ digest hexdump: %@", [crypto clearTextAsString], [digests objectAtIndex:n], [digest hexval]);
	}
	
	NSLog(@" ");
	NSLog(@" ");
	NSLog(@" ");
	
	[crypto release];
	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	// Load public and private key for next 2 tests...
	
	// DO NOT use the public/private keys from this project in your own application
	
	// You can generate your own private key by running the following command in the terminal:
	// openssl genrsa -out private.pem 2048
	//
	// Where 2048 is the size of the private key.
	// You may used a bigger number.
	// It is probably a good recommendation to use at least 1024...

	// Then to extract the public key from the private key, use the following command:
	// openssl rsa -in private.pem -out public.pem -outform PEM -pubout
	
	// If you are unfamiliar with the basics of Public-key cryptography, a great tutorial can be found on wikipedia:
	// http://en.wikipedia.org/wiki/Public-key_cryptography
	
    NSData *privateKeyData = [SSCrypto generateRSAPrivateKeyWithLength:2048];
    NSLog(@"privateKeyData: \n%s", [privateKeyData bytes]);
    NSData *publicKeyData = [SSCrypto generateRSAPublicKeyFromPrivateKey:privateKeyData];
    NSLog(@"publicKeyData: \n%s", [publicKeyData bytes]);

//	NSString *publicKeyPath  = @"/tmp/public-1199732482.pem";
//	NSString *privateKeyPath = @"/tmp/private-1199732482.pem";
//
//	NSData *publicKeyData  = [NSData dataWithContentsOfFile:publicKeyPath];
//	NSData *privateKeyData = [NSData dataWithContentsOfFile:privateKeyPath];
	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	// Test 4: Sign (encrypt), and then verify (decrypt) a string
	
	// Signing is the same as running the following command in the terminal:
	// echo -n "The duck quacks at daybreak" | openssl rsautl -sign -inkey Privatekey.pem | openssl enc -base64
	
	// Verifying is the same as running the following command in the terminal:
	// echo -n "Q102..." | openssl enc -base64 -d | openssl rasutl -verify -inkey PUBKEY.pem -pubin
	
	crypto = [[SSCrypto alloc] initWithPublicKey:publicKeyData privateKey:privateKeyData];
	
	NSString *secretPhrase = @"The duck quacks at daybreak";
	[crypto setClearTextWithString:secretPhrase];
	
	NSData *signedTextData = [crypto sign];
	NSData *verifiedTextData = [crypto verify];
	
	NSLog(@"Secret Phrase: %@", secretPhrase);
	NSLog(@"Signed (Encrypted using private key): %@", [signedTextData encodeBase64]);
	NSLog(@"Verified (Decrypted using public key): %s", [verifiedTextData bytes]);
	
	// Note: we could also have output the verifiedTextData (clearText) by doing the following:
	// NSLog(@"Now Verified: %@", [crypto clearTextAsString]);
	
	NSLog(@" ");
	NSLog(@" ");
	NSLog(@" ");
	
	[crypto release];
	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	// Test 5: Encrypt, and then decrypt a string
	
	// Encrypting is the same as running the following command in the terminal:
	// echo -n "Billy likes Mandy" | openssl rsautl -encrypt -inkey PUBKEY.pem -pubin | openssl enc -base64
	// 
	// Note: you'll get a different encryption everytime, so don't expect them to be the same...
	
	// Decrypting is the same as running the following command in the terminal:
	// echo -n "SLSbd6..."| openssl enc -base64 -d | openssl rsautl -decrypt -inkey Privatekey.pem
	
	crypto = [[SSCrypto alloc] initWithPublicKey:publicKeyData privateKey:privateKeyData];
	
	NSString *topSecret = @"Billy likes Mandy";
	[crypto setClearTextWithString:topSecret];
	
	NSData *encryptedTextData = [crypto encrypt];
	NSData *decryptedTextData = [crypto decrypt];

	NSLog(@"Top Secret: %@", topSecret);
	NSLog(@"Encrypted: %@", [encryptedTextData encodeBase64]);
	NSLog(@"Decrypted: %s", [decryptedTextData bytes]);
	
	// Note: we could also have output the decryptedTextData (clearText) by doing the following:
	// NSLog(@"Now Decrypted: %@", [crypto clearTextAsString]);
	
	NSLog(@" ");
	NSLog(@" ");
	NSLog(@" ");

	[crypto release];
	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	[pool release];
    return 0;
}
