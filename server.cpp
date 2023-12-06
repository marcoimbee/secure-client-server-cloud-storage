// ---------- INCLUDE ----------
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <math.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <dirent.h>

using namespace std;

// ---------- DEFINES ----------
#define SERVER_PORT 4242
#define BACKLOG 10              //maximum simultaneous connections
#define DIMMAX 2048
#define DIMIV 16
#define DIMTAG 16
#define KEYSIZE 2048
#define SESSION_KEY_LENGTH EVP_CIPHER_key_length(EVP_aes_128_gcm())
#define SHA256 256
#define CHUNK_DIM 1048576UL         //1MB big chunks will be sent

/*
    checkCounter():
        check the alignment of the two passed counters
        checks the wraparound case of counterS
*/
bool check_counter(unsigned long &counterS, unsigned long counterC) {
    if(counterS == ULONG_MAX) {
         cerr << "WRAPAROUND counterS" << endl;
         return false;
    }
    else if(counterC != counterS)
    {
        cerr << "counter problem --> counterS = " << counterS << " | counterC = " << counterC << endl;
        return false;
    }
    counterS++;

    return true;
}
/*
    destroy():
        deletes and deallocates the passed pointer
        the compiler optimizations are disabled during the deallocation
*/
void destroy(unsigned char * &pointer, unsigned int len)
{
    if(pointer != NULL)
    {
        #pragma optimize("", off)
        memset(pointer, 0, len);
        #pragma optimize("", on)
        free(pointer);
    }
}

/*
    checkFilename():
        checks the validity of the passed string
*/
bool checkFilename(const string& str1, bool flag)
{
    if(str1.empty()) { cerr << "Error: invalid parameter" << endl; return false; }

    if(flag)
    {
        static char ok_chars[] = "abcdefghijklmnopqrstuvwxyz"
                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             "1234567890-_.@#°()[]èé+òàù=ç§$£€!ì,;&%^";
        if(str1.find_first_not_of(ok_chars) != string::npos) { cerr << "Error: invalid parameter" << endl; return false; }
    }
    else
    {
        static char ok_chars[] = "abcdefghijklmnopqrstuvwxyz"
                                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "1234567890";
        if(str1.find_first_not_of(ok_chars) != string::npos) { cerr << "Error: invalid parameter" << endl; return false; }
    }
    return true;
}

/*
    miaMalloc():
        allocates a buffer of len length
        checks for errors in malloc()
*/
bool miaMalloc(unsigned char *&buffer, long len)
{
    buffer = (unsigned char *)malloc(len);
    if(!buffer)
    {
        cerr << "Error: miaMalloc() returned NULL" << endl;
        return false;
    }
    return true;
}

/*
    allocateANDgenerateIV():
        allocates and generates a unique initialization vector
*/
bool allocateANDgenerateIV(unsigned char *& iv, const EVP_CIPHER* cipher)
{
    if(!miaMalloc(iv, DIMIV)) return false; 
    RAND_poll();

    int ret = RAND_bytes((unsigned char*)&iv[0], DIMIV);
    if(ret != 1)
	   return false;
    return true;
}

/*
    generate_key():
        generates a pair of temporary RSA keys using openssl command line instructions
*/
void generate_key(string IDClient)
{
    system(("openssl genrsa -out SERVER_FILES/temp_" + IDClient + "_Private.pem 2048").c_str());
    system(("openssl genrsa –aes128 -out SERVER_FILES/temp_" + IDClient + "_Private.pem 2048").c_str());
    system(("openssl rsa -pubout -in SERVER_FILES/temp_" + IDClient + "_Private.pem -out SERVER_FILES/temp_" + IDClient + "_Public.pem").c_str());
}

/*
    getCertificate():
        loads the server's certificate into buffer
*/
bool getCertificate(unsigned char *buffer, long &sizeFile)
{
   bool check;

   string serverCertFilePath = "SERVER_FILES/server_cert.pem";
   FILE* serverCertFile = fopen(serverCertFilePath.c_str(), "r");
   if(!serverCertFile){
       cerr << "Error: cannot open file '" << serverCertFilePath << "' (missing?)" << endl;
       return false;
   }

   fseek(serverCertFile, 0, SEEK_END);      //getting the file's dimension
   sizeFile = ftell(serverCertFile);
   fseek(serverCertFile, 0, SEEK_SET);
   
   if(fread(buffer, 1, sizeFile, serverCertFile) != sizeFile) 
   { 
        cerr << "Error while loading the server's certificate" << endl; 
        check = false;
   }
   else
        check = true;

   fclose(serverCertFile);

   return check;
}

/*
    getRSAKey():
        loads the client's RSA temporary public key
*/
bool getRSAKey(unsigned char *tempPubK, long &sizeFile, string IDClient)
{
    bool check;

    FILE* pubkey_file = fopen( ("SERVER_FILES/temp_" + IDClient + "_Public.pem").c_str(), "r");
    if(!pubkey_file){ cerr << "Error: cannot open file SERVER_FILES/temp_" + IDClient + "_Public.pem (missing?)" << endl; return false; }

    fseek(pubkey_file, 0, SEEK_END);
    sizeFile = ftell(pubkey_file);
    fseek(pubkey_file, 0, SEEK_SET);

    if(fread(tempPubK, 1, sizeFile, pubkey_file) != sizeFile){
        cout << "Error while reading the client's public key" << endl;
        check = false;
    }else
        check = true;

    fclose(pubkey_file);
    return check;
}

/*
    removeTempKeyFile():
        removes the temporary RSA key files
*/
void removeTempKeyFile(string IDClient)
{
    remove(("SERVER_FILES/temp_" + IDClient + "_Private.pem").c_str());
    remove(("SERVER_FILES/temp_" + IDClient + "_Public.pem").c_str());
}

/*
    gcm_encrypt():
        encrypts the passed data with AES 128 in GCM mode
*/
int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, unsigned long aad_len, unsigned char *key,
                unsigned char *iv, int iv_len, unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len = 0;

    //Creating and initialising the context
    if(!(ctx = EVP_CIPHER_CTX_new())){ cerr << "Error: EVP_CIPHER_CTX_new failed" << endl; exit(1); }

    //Initialising the encryption operation
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv)){ cerr << "Error: EVP_EncryptInit failed" << endl; EVP_CIPHER_CTX_free(ctx); return -1; }

    //Providing the AAD data
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)){ cerr << "Error: EVP_EncryptUpdate failed" << endl; EVP_CIPHER_CTX_free(ctx); return -1; }

    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, iv, iv_len)){ cerr << "Error: EVP_EncryptUpdate failed" << endl; EVP_CIPHER_CTX_free(ctx); return -1; }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){ cerr << "Error: EVP_EncryptUpdate failed" << endl; EVP_CIPHER_CTX_free(ctx); return -1; }

    ciphertext_len = len;
    
    //adding the padding
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len)){ cerr << "Error: EVP_EncryptFinal failed" << endl; EVP_CIPHER_CTX_free(ctx); return -1; }
    ciphertext_len += len;

    //Getting the TAG
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, DIMTAG, tag)){ cerr << "Error: EVP_CIPHER_CTX_ctrl failed" << endl; EVP_CIPHER_CTX_free(ctx); return -1; }

    //cleaning up
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}

/*
    gcm_decrypt():
        decrypts the passed ciphertext using AES 128 in GCM mode
*/
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, unsigned long aad_len, unsigned char *tag,
                unsigned char *key, unsigned char *iv, int iv_len, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    //creating and initialising the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
    {
        EVP_CIPHER_CTX_cleanup(ctx);
        return -1;
    }

    //providing the AAD
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        EVP_CIPHER_CTX_cleanup(ctx);
        return -1;
    }

    if(!EVP_DecryptUpdate(ctx, NULL, &len, iv, iv_len))
    {
        EVP_CIPHER_CTX_cleanup(ctx);
        return -1;
    }

	//Providing the message to be decrypted, and obtaining the plaintext as output
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        EVP_CIPHER_CTX_cleanup(ctx);
        return -1;
    }
    plaintext_len = len;

    //Setting the expected tag value
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, DIMTAG, tag))
    {
        EVP_CIPHER_CTX_cleanup(ctx);
        return -1;//handleErrors(4);
    }
    
    //Finalising the decryption
    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);
    
    //cleaning up
    EVP_CIPHER_CTX_cleanup(ctx);
    if(ret > 0)         //success case
    {
        plaintext_len += len;
        return plaintext_len;
    }
    else        //fail case
        return -1;
}

/*
    extractFromMsgTheClearChunk():
        extracts from the passed message the decrypted chunk of file
*/
bool extractFromMsgTheClearChunk(unsigned char *uploadMsg, unsigned long &counterS, unsigned char *sessionKey, unsigned char *clear_chunk, int &clear_chunkLen)
{
    unsigned long counterC;
    unsigned char *encrypted_chunk;
    int encrypted_chunkLen;
    memcpy(&counterC, uploadMsg, sizeof(counterC));

    if(!check_counter(counterS, counterC))
        return false;
    
    unsigned char *iv, *tag_buf;
    if(!miaMalloc(iv, DIMIV))
        return false;
    if(!miaMalloc(tag_buf, DIMTAG))
        return false;
    memcpy(&encrypted_chunkLen, uploadMsg + sizeof(counterC), sizeof(encrypted_chunkLen));
    if(!miaMalloc(encrypted_chunk, encrypted_chunkLen))
        return false;
    
    memcpy(encrypted_chunk, uploadMsg + sizeof(counterC) + sizeof(encrypted_chunkLen), encrypted_chunkLen);
    memcpy(iv, uploadMsg + sizeof(counterC) + sizeof(encrypted_chunkLen) + encrypted_chunkLen, DIMIV);
    memcpy(tag_buf, uploadMsg + sizeof(counterC) + sizeof(encrypted_chunkLen) + encrypted_chunkLen + DIMIV, DIMTAG);
    
    clear_chunkLen = gcm_decrypt(encrypted_chunk, encrypted_chunkLen, (unsigned char *)&counterC, sizeof(counterC), tag_buf, sessionKey, iv, DIMIV, clear_chunk);
    if(clear_chunkLen < 0 )  { cerr << "Error: file chunk decryption failed " << endl; return false; }

    return true;
}
                                                    
/*
    checkM3():
        checks the validity of the M3 message of the key establishment phase

    M3: [ Ns, iv, encryptedSessionKLen, Enc(K, TempKpubS), ( Ns || Enc(K, TempKpubS) )signed_w_privkC ]
*/
bool checkM3(unsigned char *M3, unsigned int Ns, string IDClient, unsigned char *&sessionKey)
{
    unsigned int ivLen = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    unsigned char *iv;
    if(!miaMalloc(iv, ivLen))
        return false;
    memcpy(iv, M3, ivLen);
    
    int encryptedSessionKLen;
    memcpy(&encryptedSessionKLen, M3 + ivLen, sizeof(encryptedSessionKLen));
    
    unsigned char *encryptedSessionK;
    if(!miaMalloc(encryptedSessionK, encryptedSessionKLen))
        return false;
    memcpy(encryptedSessionK,  M3 + ivLen + sizeof(encryptedSessionKLen), encryptedSessionKLen);
    
    //loading the client's TEMPORARY private key, generated by the server at the previous message step
    //the server will use the temporary private key ASSOCIATED to the key that was sent in M2 to the client, to decrypt the encrypted session key generated by the client
    FILE *tempPrivClientFile = fopen(("SERVER_FILES/temp_" + IDClient + "_Private.pem").c_str(), "r");
    if(!tempPrivClientFile) { cerr << "Error: fopen( tempPrivk_" << IDClient << ".pem" << endl; return false; }
    EVP_PKEY* tempClientPrivKey = PEM_read_PrivateKey(tempPrivClientFile, NULL, NULL, NULL);
    fclose(tempPrivClientFile);
    if(!tempClientPrivKey){ cerr << "Error: PEM_read_PUBKEY returned NULL" << endl; return false; }
    
    int encryptedKLen = EVP_PKEY_size(tempClientPrivKey);
    unsigned char *signature;
    if(!miaMalloc(signature, SHA256))
        return false;
    memcpy(signature, M3 + ivLen + sizeof(encryptedSessionKLen) + encryptedSessionKLen + encryptedKLen, SHA256);
    
    FILE *clientPubKeyFile = fopen(("SERVER_FILES/client_pubkeys/pubk_" + IDClient + ".pem").c_str(), "r");
    if(!clientPubKeyFile) { cerr << "Error while opening the client's temporary public key file" << endl; return false; }
    EVP_PKEY* clientPubkey = PEM_read_PUBKEY(clientPubKeyFile, NULL, NULL, NULL);
    fclose(clientPubKeyFile);
    if(!clientPubkey){ cerr << "Error: PEM_read_PUBKEY returned NULL" << endl; return false; }
    
    unsigned char *clear_buf; //buffer in the clear that was signed by client in M3
    unsigned int clear_size = sizeof(Ns) + encryptedSessionKLen; //SHA256
    if(!miaMalloc(clear_buf, clear_size))
        return false;
    memcpy(clear_buf, &Ns, clear_size);
    memcpy(clear_buf + sizeof(Ns), M3 + ivLen + sizeof(encryptedSessionKLen), encryptedSessionKLen);
    
    //CONTEXT FOR SIGNATURE VERIFY
    const EVP_MD* md = EVP_sha256();
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    int ret;
    if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; return false; }

    // verifying the plaintext
    ret = EVP_VerifyInit(md_ctx, md);
    if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << endl; return false; }
    ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);  
    if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << endl; return false; }
    ret = EVP_VerifyFinal(md_ctx, signature, SHA256, clientPubkey);
    if(ret == -1){  cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)" << endl; return false; }
    else if(ret == 0){ cerr << "Error: invalid M3 signature" << endl; return false; }

    //deallocating the signature context
    EVP_MD_CTX_free(md_ctx);
    
    //decryption of the session key
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) { cerr << "Error: EVP_CIPHER_CTX_new" << endl; return false; }
    
    unsigned char *encryptedK;
    if(!miaMalloc(encryptedK, encryptedKLen))
        return false;
    memcpy(encryptedK, M3 + ivLen + sizeof(encryptedSessionKLen) + encryptedSessionKLen, encryptedKLen);
    
    ret = EVP_OpenInit(ctx, EVP_aes_128_cbc(), encryptedK, encryptedKLen, iv, tempClientPrivKey);
    if(!ret) { cerr << "Error: EVP_OpenInit" << endl; return false; }
    
    int decr_bytes = 0;
    int tot_decr = 0;
    if(!miaMalloc(sessionKey, encryptedSessionKLen))
        return false;
    
    ret = EVP_OpenUpdate(ctx, sessionKey, &decr_bytes, encryptedSessionK, encryptedSessionKLen);
    if(!ret) { cerr << "Error: EVP_OpenUpdate" << endl; return false; }
    tot_decr += decr_bytes;
    
    ret = EVP_OpenFinal(ctx, sessionKey + tot_decr, &decr_bytes);
    if(!ret) { cerr << "Error: EVP_OpenFinal" << endl; return false; }
    tot_decr += decr_bytes;
    
    //DELETING THE INFORMATIONS
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(tempClientPrivKey);

    free(encryptedK);
    free(encryptedSessionK);
    free(iv);
    memset(clear_buf, '\0', clear_size);
    free(clear_buf);
    memset(M3, '\0', DIMMAX);
    remove(("SERVER_FILES/temp_" + IDClient + "_Private.pem").c_str());
    remove(("SERVER_FILES/temp_" + IDClient + "_Public.pem").c_str());
    
    return true;    
}

/*
    buildM2():
        builds the M2 message that will be sent to the client in the key establishment phase
*/
bool buildM2(string IDClient, int comm_socket, unsigned int Ns, unsigned int Nc)
{
    unsigned char serverCert[DIMMAX] = {0};
    long serverCertSize;
    if(!getCertificate(serverCert, serverCertSize)) { cerr << "Error while loading the server's certificate" << endl; return false; }
               
    //construction of M2
    unsigned char *M2;
    if(!miaMalloc(M2, 2 * KEYSIZE))
        return false;
    memset(M2, '\0', DIMMAX);
        
    //server's certificate
    unsigned char certServer[DIMMAX] = {0};
    memcpy(certServer, &serverCertSize, sizeof(long));
    memcpy(certServer + sizeof(long), &serverCert, serverCertSize);

    //temporary RSA public key
    long RSAKeyLength;
    unsigned char tempPubK[KEYSIZE] = {0};
    if(!getRSAKey(tempPubK, RSAKeyLength, IDClient)){ cerr << "Error while loading the temp RSA public key" << endl; return false; }

    //loading server's private rsa key
    FILE *server_privKey = fopen("SERVER_FILES/privk_server.pem", "r");
    if(!server_privKey){ cerr << "Error: cannot open file server_privkey.pem" << endl; return false; }
    EVP_PKEY *privKey = PEM_read_PrivateKey(server_privKey, NULL, NULL, NULL);
    fclose(server_privKey);
    if(!privKey){cerr << "Error: PEM_read_PrivateKey returned NULL" << endl;  return false; }

    const EVP_MD *md = EVP_sha256();

    //creating the signature context
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL" << endl;  return false; }

    //allocate the buffer for signature
    unsigned char* signature_buffer;
    if(!miaMalloc(signature_buffer, EVP_PKEY_size(privKey)))
        return false;

    //allocating buffer to be signed
    unsigned char *buffer_to_sign;
    if(!miaMalloc(buffer_to_sign, KEYSIZE + sizeof(unsigned int)))
        return false;

    //copying elements into the buffer
    memcpy(buffer_to_sign, tempPubK, KEYSIZE);
    memcpy(buffer_to_sign + KEYSIZE, &Nc, sizeof(unsigned int));

    //signing
    if(!EVP_SignInit(md_ctx, md)){cerr << "Error: EVP_SignInit returned 0" << endl;  return false; }
    if(!EVP_SignUpdate(md_ctx, buffer_to_sign, KEYSIZE + sizeof(unsigned int))){cerr << "Error: EVP_SignUpdate returned 0" << endl;  return false; }
    unsigned int signature_size;
    if(!EVP_SignFinal(md_ctx, signature_buffer, &signature_size, privKey)){cerr << "Error: EVP_SignFinal returned 0" << endl;  return false; }

    //deleting the digest and the private key from memory
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(privKey);
    
    memcpy(M2, &Ns, sizeof(Ns));
    memcpy(M2 + sizeof(Ns), &serverCertSize, sizeof(serverCertSize));
    memcpy(M2 + sizeof(Ns) + sizeof(serverCertSize), &serverCert, serverCertSize);
    memcpy(M2 + sizeof(Ns) + sizeof(serverCertSize) + serverCertSize, tempPubK, KEYSIZE);
    memcpy(M2 + sizeof(Ns) + sizeof(serverCertSize) + serverCertSize + KEYSIZE, signature_buffer, signature_size);

    if(send(comm_socket, (void*)M2, 2*KEYSIZE, MSG_WAITALL) != 2*KEYSIZE) { cerr <<"Error during the M2 send" << endl;  return false; }

    free(M2);
    free(buffer_to_sign);
    free(signature_buffer);
    memset(tempPubK, '\0', KEYSIZE);

    return true;    
}

/*
    sendACK():
        sends an ACK message to the client
        the message is specified as a parameter
*/
bool sendACK(unsigned char *plaintext, int plaintextLen, unsigned char *sessionKey, unsigned long &counterS, int comm_socket)
{
    unsigned char ackMsg[DIMMAX] = {0};
    unsigned char *iv;
	unsigned char *ciphertext;
	unsigned char *tag_buf;
	int ciphertextLen;
	if(!miaMalloc(ciphertext, plaintextLen + EVP_CIPHER_block_size(EVP_aes_128_gcm())))
	    return false;
	if(! allocateANDgenerateIV(iv, EVP_aes_128_gcm()) )
	    return false;
	if(!miaMalloc(tag_buf, DIMTAG))
	    return false;
	
	ciphertextLen = gcm_encrypt(plaintext, plaintextLen, (unsigned char *)&counterS, sizeof(counterS), sessionKey, iv, DIMIV, ciphertext, tag_buf);
	if(ciphertextLen < 0)
	{
	    cerr<<"Error during ACK encryption"<<endl;
	    return false;
	}

	memcpy(ackMsg, &counterS, sizeof(counterS));
    memcpy(ackMsg + sizeof(counterS), &ciphertextLen, sizeof(ciphertextLen));
    memcpy(ackMsg + sizeof(counterS) + sizeof(ciphertextLen), ciphertext, ciphertextLen);
    memcpy(ackMsg + sizeof(counterS) + sizeof(ciphertextLen) + ciphertextLen, iv, DIMIV);
    memcpy(ackMsg + sizeof(counterS) + sizeof(ciphertextLen) + ciphertextLen + DIMIV, tag_buf, DIMTAG);
    
    if(send(comm_socket, (void*)ackMsg, DIMMAX, MSG_WAITALL) != DIMMAX) { cerr << "Error during the sendACK send" << endl; return false; }
    counterS++;

    return true;
}

/*
    readDirectory():
        reads the content of the specified directory and creates a string with the filenames
*/
int readDirectory(string IdClient, string &list)
{
    DIR *dir;
    struct dirent *diread;

    if((dir = opendir(("SERVER_FILES/" + IdClient + "/").c_str())) != nullptr)      //opening the directory
    {
        list += "list";
        while ((diread = readdir(dir)) != nullptr) 
        {
            if(((string)(diread->d_name) == "." || (string)(diread->d_name) == "..")) continue;
            list += "|" + (string)diread->d_name;           //concatenating the current filename
        }
        closedir(dir);
    }
    else
    {
        cerr << "Error: opendir returned NULL" << endl;
        return 0;
    }

    return 1;
}

/*
    executeList():
        executes the 'list' command. Sends to the client a string containing the filenames of the files contained in his personal folder
*/
int executeList(string IdClient, unsigned char* sessionKey, unsigned long &counterS, int comm_socket)
{
    string list;
    unsigned char listMsg[DIMMAX] = {0};
    unsigned char *iv;
	unsigned char *ciphertext;
	unsigned char *tag_buf;
	int ciphertextLen;

    if(!readDirectory(IdClient, list)){ cout << "Error: readDirectory returned 0" << endl; return -1; }

	if(!miaMalloc(ciphertext, list.length() + EVP_CIPHER_block_size(EVP_aes_128_gcm()) )) return -1;
	if(!allocateANDgenerateIV(iv, EVP_aes_128_gcm())) return -1;
	if(!miaMalloc(tag_buf, DIMTAG)) return -1;
	
	ciphertextLen = gcm_encrypt((unsigned char*)list.c_str(), list.length(), (unsigned char *)&counterS, sizeof(counterS), sessionKey, iv, DIMIV, ciphertext, tag_buf);
	if(ciphertextLen < 0)
	{
	    cerr<<"Error encrypting reply to 'list' command" << endl;
	    return -1;
	}

	memcpy(listMsg, &counterS, sizeof(counterS));
    memcpy(listMsg + sizeof(counterS), &ciphertextLen, sizeof(ciphertextLen));
    memcpy(listMsg + sizeof(counterS) + sizeof(ciphertextLen), ciphertext, ciphertextLen);
    memcpy(listMsg + sizeof(counterS) + sizeof(ciphertextLen) + ciphertextLen, iv, DIMIV);
    memcpy(listMsg + sizeof(counterS) + sizeof(ciphertextLen) + ciphertextLen + DIMIV, tag_buf, DIMTAG);
    
    if(send(comm_socket, (void*)listMsg, DIMMAX, MSG_WAITALL) != DIMMAX) { cerr << "Error during the executeList send" << endl; return false; }
    counterS++; 

    return 1;
}

/*
    buildDownloadMessage():
        builds the message that will be sent as a response to the 'download' command
*/
void builDownloadMessage(unsigned char *downloadMsg, unsigned long counterS, int encrypted_chunkLen, unsigned char *encrypted_chunk, unsigned char *iv, unsigned char *tag_buf)
{
    memcpy(downloadMsg, &counterS, sizeof(counterS));
    memcpy(downloadMsg + sizeof(counterS), &encrypted_chunkLen, sizeof(encrypted_chunkLen));
    memcpy(downloadMsg + sizeof(counterS) + sizeof(encrypted_chunkLen), encrypted_chunk, encrypted_chunkLen);
    memcpy(downloadMsg + sizeof(counterS) + sizeof(encrypted_chunkLen) + encrypted_chunkLen, iv, DIMIV);
    memcpy(downloadMsg + sizeof(counterS) + sizeof(encrypted_chunkLen) + encrypted_chunkLen + DIMIV, tag_buf, DIMTAG);
}

/*
    encryptChunk():
        encrypts the passed file chunk
*/
bool encryptChunk(unsigned char *chunk, unsigned int chunkLen, unsigned long counterS, unsigned char *session_key, unsigned char *encrypted_chunk, int &encrypted_chunkLen, unsigned char * iv, unsigned char * tag_buf)
{   
	memset(encrypted_chunk, '\0', CHUNK_DIM + (DIMMAX/2));

    encrypted_chunkLen = gcm_encrypt(chunk, chunkLen, (unsigned char *)&counterS, sizeof(counterS), session_key, iv, DIMIV, encrypted_chunk, tag_buf);
    if(encrypted_chunkLen < 0)
    {
        cerr<<"Error encrypting the file chunk"<<endl;
        return false;
    }
    return true;
}

/*
    executeDownload():
    executed the 'download' command
        sends the specified file's chunks to the client
*/
int executeDownload (string fileName, unsigned char* session_key, unsigned long &counterS, int comm_socket, string IDClient) 
{
    if(! checkFilename(fileName, true))       //checking the validity of the filename
    {
        if(!sendACK((unsigned char *)"Error-Invalid filename\0", strlen("Error-Invalid filename\0"), session_key, counterS, comm_socket))
            return -1;
        return 0;
    }
    
    FILE*  to_be_downloaded = fopen( ("SERVER_FILES/" + IDClient + "/" + fileName).c_str(), "rb");
    if(!to_be_downloaded)       //checking if the specified file exists
    {
        if(!sendACK((unsigned char *)"Error-The specified file does not exist\0", strlen("Error-The specified file does not exist\0"), session_key, counterS, comm_socket))
            return -1;
        return 0;
    }

    fseek(to_be_downloaded, 0, SEEK_END);           //getting the file dimension
    unsigned long file_dim = ftell(to_be_downloaded);
    fseek(to_be_downloaded, 0, SEEK_SET);
    string ACKDownload = "OK-" + to_string(file_dim);
    
    if(!sendACK( ((unsigned char *)ACKDownload.c_str()), strlen(ACKDownload.c_str()), session_key, counterS, comm_socket))
    {
        cout<<"Error during download's sendACK"<<endl;
        return -1;
    }
    

    //**************** STARTING OF THE DOWNLOAD PHASE: [ Read CHUNKi --> Encrypt CHUNKi --> Send CHUNKi ] ****************

    unsigned char chunk[CHUNK_DIM];
    unsigned int tot_chunks = floor(file_dim / CHUNK_DIM);
    unsigned char *iv, *tag_buf;
    unsigned char encrypted_chunk[CHUNK_DIM + (DIMMAX/2)];
    unsigned char downloadMsg[CHUNK_DIM + DIMMAX] = {0};
    if(!miaMalloc(tag_buf, DIMTAG)) return -1;
    
    int encrypted_chunkLen;
    cout<<"Sending " << tot_chunks + 1 << " chunks to client ..."<<endl;
    cout<<"[";
    for(unsigned int i = 0; i < tot_chunks; i++)
    {
        fread(&chunk, 1, CHUNK_DIM, to_be_downloaded);  //lettura dei chunk di dimensione CHUNK_DIM   

        free(iv); 
        if(!allocateANDgenerateIV(iv, EVP_aes_128_gcm()))
        {
            cerr<<"Error while allocating/generating download's IV" <<endl;
            return -1;
        }

        if(!encryptChunk(chunk, CHUNK_DIM, counterS, session_key, encrypted_chunk, encrypted_chunkLen, iv, tag_buf))
        {
            cerr<<"Error while encrypting one of the download's chunks"<<endl;
            return -1;
        } 
        
        builDownloadMessage(downloadMsg, counterS, encrypted_chunkLen, encrypted_chunk, iv, tag_buf);
        
        if(send(comm_socket, (void*)downloadMsg, CHUNK_DIM + DIMMAX, MSG_WAITALL) != (CHUNK_DIM + DIMMAX )) { cerr << "Error during the executeUpload send" << endl; return -1; }
        counterS++;

        cout<<".";
    }

    memset(&chunk, 0, CHUNK_DIM);
    unsigned int byteToRead = file_dim - (CHUNK_DIM*tot_chunks);
    if(byteToRead != 0)
    {
        free(iv);
        if(!allocateANDgenerateIV(iv, EVP_aes_128_gcm()))
        {
            cerr<<"Error while allocating/generating download's IV"<<endl;
            return -1;
        }
        
        fread(&chunk, 1, byteToRead, to_be_downloaded);

        if(!encryptChunk(chunk, byteToRead, counterS, session_key, encrypted_chunk, encrypted_chunkLen, iv, tag_buf))
            return -1;

        builDownloadMessage(downloadMsg, counterS, encrypted_chunkLen, encrypted_chunk, iv, tag_buf);
        
        if(send(comm_socket, (void*)downloadMsg, CHUNK_DIM + DIMMAX, MSG_WAITALL) != (CHUNK_DIM + DIMMAX )) { cerr << "Error during the executeUpload send" << endl; return -1; }
        counterS++;

        if(tot_chunks == 0)
            cout << ".";
    }

    cout<<"]"<<endl<<"Download completed"<<endl;
    fclose(to_be_downloaded);

    return 1;
}

/*
    executeDelete():
        executed the 'delete' command
*/
int executeDelete (string fileName, unsigned char* session_key, unsigned long &counterS, int comm_socket, string IDClient) 
{
    if(! checkFilename(fileName, true))           //checking the passed filename
    {
        sendACK((unsigned char *)"Error-Invalid filename\0", strlen("Error-Invalid filename\0"), session_key, counterS, comm_socket);
        return 0;
    }
    
    FILE*  toDelete = fopen( ("SERVER_FILES/" + IDClient + "/" + fileName).c_str(), "r");
    if(!toDelete)
    {
        sendACK((unsigned char *)"Error-The specified file does not exist\0", strlen("Error-The specified file does not exist\0"), session_key, counterS, comm_socket);
        return 0;
    }
    fclose(toDelete);
    
    string filePath = "SERVER_FILES/" + IDClient + "/" + fileName;
    bool status = remove(filePath.c_str());

    if(status == 0)
    {
        if(!sendACK((unsigned char *)"OK\0", strlen("OK\0"), session_key, counterS, comm_socket))
            return -1;
    }
    else
    {
        if(!sendACK((unsigned char *)"Error-Unsuccessful delete\0", strlen("Error-Unsuccessful delete\0"), session_key, counterS, comm_socket))
            return -1;
    }
    
    return 1;
}

/*
    executeRename():
        executes the 'rename' command
*/
int executeRename (string oldFileName, string newFileName, unsigned char* session_key, unsigned long &counterS, int comm_socket, string IDClient) 
{
    if( (! checkFilename(newFileName, true)) || (!checkFilename(oldFileName, true)) )        //checking the specified filename
    {
        if(!sendACK((unsigned char *)"Error-Invalid filename\0", strlen("Error-Invalid filename\0"), session_key, counterS, comm_socket))
            return -1;
        return 0;
    }

    FILE *toRename = fopen(("SERVER_FILES/" + IDClient + "/" + oldFileName).c_str(), "r");          //checking if the file actually exists
    if(!toRename)
    {
        if(!sendACK((unsigned char *)"Error-The specified file does not exist\0", strlen("Error-The specified file does not exist\0"), session_key, counterS, comm_socket))
            return -1;
        return 0;
    }
    fclose(toRename);

    string oldFileNamePath = "SERVER_FILES/" + IDClient + "/" + oldFileName;
    string newFileNamePath = "SERVER_FILES/" + IDClient + "/" + newFileName;

    int renameOutcome = rename(oldFileNamePath.c_str(), newFileNamePath.c_str());

    if(renameOutcome != 0)
    {
        if(!sendACK((unsigned char *)"Error-Unsuccessful rename\0", strlen("Error-Unsuccessful rename\0"), session_key, counterS, comm_socket))
            return -1;
    }
    else
    {
        if(!sendACK((unsigned char *)"OK\0", strlen("OK\0"), session_key, counterS, comm_socket))
            return -1;
    }
    return 1;
}

/*
    executeUpload():

*/
int executeUpload (string fileName, unsigned long dimFile, unsigned char* sessionKey, unsigned long &counterS, int comm_socket, string IDClient) 
{
    unsigned int tot_chunks = floor(dimFile / CHUNK_DIM);
    unsigned char uploadMsg[CHUNK_DIM + DIMMAX] = {0};
    unsigned char *encrypted_chunk;
    unsigned char clear_chunk[CHUNK_DIM] = {0};
    int encrypted_chunkLen, clear_chunkLen;
    string ackMsg;
    if( checkFilename(fileName, true))        //checking the passed filename
    {
        if(!sendACK((unsigned char *)"OK-\0", strlen("OK-\0"), sessionKey, counterS, comm_socket))
            return -1;
    }
    else
    {
        if(!sendACK((unsigned char *)"Error-Invalid filename\0", strlen("Error-Invalid filename\0"), sessionKey, counterS, comm_socket))
            return -1;
        return 0;
    }
    
    //If the file already exists on server side, it will be deleted.
    FILE *uploadedFile = fopen(("SERVER_FILES/" + IDClient + "/" + fileName).c_str(), "r");
    if(uploadedFile)
        remove(("SERVER_FILES/" + IDClient + "/" + fileName).c_str()); 
    uploadedFile = fopen( ("SERVER_FILES/" + IDClient + "/" + fileName).c_str(), "ab");
    if(!uploadedFile)
    {
        cerr << "Error while opening the passed filename (upload)" << endl;
        return -1;
    }
    cout << "Waiting " << tot_chunks + 1 <<" chunks from client"<< endl;
    cout << "[";
    for(unsigned int i = 0; i < tot_chunks; i++)
    {
        if((recv(comm_socket, (void*)&uploadMsg, CHUNK_DIM + DIMMAX, MSG_WAITALL) ) != ( CHUNK_DIM + DIMMAX))
        {
            cerr<<"Error while receiving the " << i << "-th chunk" << endl;
            return -1;
        }

        if(!extractFromMsgTheClearChunk(uploadMsg, counterS, sessionKey, clear_chunk, clear_chunkLen)) 
            return -1;

        if(fwrite(clear_chunk, 1, clear_chunkLen, uploadedFile) != clear_chunkLen)
        {
            cerr << "Error while writing the " << i << "-th chunk" << endl;
            return -1;
        }
        memset(&uploadMsg, 0, CHUNK_DIM + DIMMAX);
        
        cout<<".";
    }
       
    unsigned int remainingBytes = dimFile - (CHUNK_DIM * tot_chunks);
    if(remainingBytes != 0)
    {
        if( recv(comm_socket, (void*)&uploadMsg, (CHUNK_DIM + DIMMAX) ,MSG_WAITALL ) != (CHUNK_DIM + DIMMAX)) // No Wraparound possible
        { 
            cerr << "Error while receiving the last chunk" << endl;
            return -1;
        }
        
        if(!extractFromMsgTheClearChunk(uploadMsg, counterS, sessionKey, clear_chunk, clear_chunkLen))
            return -1;
        
        if(fwrite(clear_chunk, 1, clear_chunkLen, uploadedFile) != clear_chunkLen) 
        {
            cerr << "Error while writing the last chunk" << endl;
            return -1;
        }
        if(tot_chunks == 0)
            cout<<".";
    }
    cout<<"]"<<endl<<"Upload completed" << endl;

    fclose(uploadedFile);
    
    return 1;
}

// --------- MAIN ---------
int main(int argc, char* argv[])
{
    SSL_load_error_strings();

    //server parameters
    struct sockaddr_in server_address;
    const int options = true;

    //client-server comm vars
    struct sockaddr_in client_address;
    socklen_t clientaddr_length;
    uint8_t check;
    int listening_socket;
    int comm_socket; 
    pid_t pid_requests;

    //init of the server's params
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr);

    //listening socket, TCP, blocking
    listening_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(listening_socket < 0){
        cerr << "Error during socket creation" << endl;
        exit(-1);
    }

    //binding of server's data
    check = setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR, &options, sizeof(options));
    if(check < 0){
        cerr << "Error during setsockopt operation" << endl;
        exit(-1);
    }
    check = bind(listening_socket, (struct sockaddr*)&server_address, sizeof(server_address));
    if(check < 0){
        cerr << "Error during bind operation" << endl;
        exit(-1);
    }

    //setting up the listening socket
    check = listen(listening_socket, BACKLOG);       //backlog = max connected clients
    if(check < 0){
        cerr << "Error during listen operation" << endl;
        exit(-1);
    }
    clientaddr_length = sizeof(client_address);


    //LISTENING CYCLE
    while(true)
    {
        cout<<"Waiting for connections..."<<endl;

        comm_socket = accept(listening_socket, (struct sockaddr*)&client_address, &clientaddr_length);      //accepting one incoming connection

        cout << "A client has connected to the server." << endl;

        unsigned char *plaintext = NULL, *ciphertext = NULL, *iv = NULL, *tag_buf = NULL;
        int ciphertextLen;
        int plaintextLen;

        pid_requests = fork();          //creating the child process that will server the client's request
        
        //CHILD PROCESS
        if(pid_requests == 0)
        {   
            close(listening_socket);        //the children don't need the listening socket

            unsigned int Nc;
            unsigned char M1[DIMMAX];
	        memset(M1, '\0', DIMMAX);

            // ******************** KEY ESTABLISHMENT ********************
            if(recv(comm_socket, (void*)&M1, DIMMAX, MSG_WAITALL) == -1 ) { cerr << "Error during the M1 receive" << endl; exit(1); } 

            memcpy(&Nc, M1, sizeof(unsigned int));
            string IDClient((char *)M1 + sizeof(unsigned int));

            if (!checkFilename(IDClient.c_str(), false))
                exit(1);

            RAND_poll();
            unsigned int Ns;
            if ( RAND_bytes((unsigned char*)&Ns, sizeof(Ns)) != 1) { cerr << "Error: RAND_bytes failed" << endl; exit(1); }
            
            //generating RSA temporary key pair
            generate_key(IDClient);

            //building + sending M2
            if(!buildM2(IDClient, comm_socket, Ns, Nc))
                removeTempKeyFile(IDClient);

            //receiving M3
            unsigned char M3[DIMMAX] = {0};
            if(recv(comm_socket, (void*)&M3, DIMMAX, MSG_WAITALL) != DIMMAX)
            {
                cerr << "Error during the M3 receive" << endl;
                removeTempKeyFile(IDClient);            //if filure, deletes the created keys
                exit(1);
            } 
            
            //M3: [ Ns, encryptedSessionKLen, Enc(K, TempKpubS), signedLen, (Ns)signed_w_privkC ]
            unsigned char *sessionKey;
            if(!checkM3(M3, Ns, IDClient, sessionKey))          //checking the M3 message
            {
                destroy(sessionKey, SESSION_KEY_LENGTH);
                memset(M3, '\0', DIMMAX);
                exit(1);
            }

            //removing the temporary RSA key pair, if all went well up to now
            removeTempKeyFile(IDClient);
            
            plaintextLen = DIMMAX;
            char msg[DIMMAX];
            unsigned long counterS = 0;
            unsigned long counterC = 0;
            int ret = 0;
            if(!miaMalloc(plaintext, plaintextLen) || (!miaMalloc(tag_buf, DIMTAG)) || (!miaMalloc(iv, DIMIV)) )
            {
                destroy(sessionKey, SESSION_KEY_LENGTH);            //if anything goes wrong, the session key must be destroyes
                cerr<<"Error while allocating the session key"<<endl;
                exit(1);
            }
            memset(msg, 0, DIMMAX);
            memset(plaintext, 0, plaintextLen);
            cout<<"Secure session established with " << IDClient <<endl;
            //communication SESSION cycle
            while(true)
            {  
                check = recv(comm_socket, (void*)&msg, DIMMAX, MSG_WAITALL);        //receiving a client's message
                if(check != -1)
                {
                    // (counter | ciphertextlen | ciphertext | iv | tag)
                    memcpy(&counterC, msg, sizeof(counterC));
                    if(!check_counter(counterS, counterC))
                    {
                         destroy(sessionKey, SESSION_KEY_LENGTH);
                         exit(1);
                    }
                    memcpy(&ciphertextLen, msg + sizeof(unsigned long), sizeof(unsigned int));
                    if(!miaMalloc(ciphertext, ciphertextLen))
                    {
                        destroy(sessionKey, SESSION_KEY_LENGTH);
                        exit(1);
                    }
                    memcpy(ciphertext, msg + sizeof(unsigned int) + sizeof(unsigned long), ciphertextLen);
                    memcpy(iv, msg + sizeof(unsigned int) + sizeof(unsigned long) + ciphertextLen, DIMIV);
                    memcpy(tag_buf, msg + sizeof(unsigned int) + sizeof(unsigned long) + ciphertextLen + DIMIV, DIMTAG);
                    
                    //decrypting the ciphertext which comes with the session msg
                    plaintextLen = gcm_decrypt(ciphertext, ciphertextLen, (unsigned char *) &counterC, sizeof(unsigned long), tag_buf, sessionKey, iv, DIMIV, plaintext);
                    if( plaintextLen < 0)
                    {
                        cerr << "Error while decrypting a session message ciphertext" << endl;
                        destroy(sessionKey, SESSION_KEY_LENGTH);
                        exit(1);
                    }
                    plaintext[plaintextLen] = '\0';
                    
                    // [ upload NomeFile DimFile]
                    // [ download NomeFile \0]
                    // [ list \0 \0]
                    // [ rename OldName NewName]
                    // [ delete NomeFile \0]
                    // [ logout \0 \0]
                    
                    //splitting the received plaintext
                    char *token = strtok((char *)plaintext, " ");

                    //possible commands
                    if(!strncmp(token, "list", strlen(token)))
                    {
                        memset(plaintext, 0, plaintextLen);
                        if(executeList(IDClient, sessionKey, counterS, comm_socket) < 0)
                        {
                            destroy(plaintext, plaintextLen);
                            destroy(sessionKey, SESSION_KEY_LENGTH);
                            exit(1);
                        }
                    }
                    else if(!strncmp(token, "upload", strlen(token)))
                    {
                        if((token = strtok(NULL, " ")) == NULL) { cerr << "Error in the command syntax" << endl;}
                        string fileName(token);
                        
                        if((token = strtok(NULL, " ")) == NULL) { cerr << "Error in the command syntax" << endl;}
                        unsigned long dimFile = atol(token);
                        
                        memset(plaintext, 0, plaintextLen);
                        if(executeUpload(fileName, dimFile, sessionKey, counterS, comm_socket, IDClient) < 0)
                        {
                            destroy(plaintext, plaintextLen);
                            destroy(sessionKey, SESSION_KEY_LENGTH);
                            exit(1);
                        }
                    }
                    else if(!strncmp(token, "download", strlen(token)))
                    {
                        if((token = strtok(NULL, " ")) == NULL) { cerr << "Error in the command syntax" << endl;}
                        string fileName(token);
                        memset(plaintext, 0, plaintextLen);
                        if(executeDownload(fileName, sessionKey, counterS, comm_socket, IDClient) < 0)
                        {
                            destroy(plaintext, plaintextLen);
                            destroy(sessionKey, SESSION_KEY_LENGTH);
                            exit(1);
                        }
                    }
                    else if(!strncmp(token, "rename", strlen(token)))
                    {
                        if((token = strtok(NULL, " ")) == NULL) { cerr << "Error in the command syntax" << endl;}
                        string oldFileName(token);
                        
                        if((token = strtok(NULL, " ")) == NULL) { cerr << "Error in the command syntax" << endl;}
                        string newFileName(token);
                        
                        memset(plaintext, 0, plaintextLen); 
                        if(executeRename(oldFileName, newFileName, sessionKey, counterS, comm_socket, IDClient) < 0)
                        {
                            destroy(plaintext, plaintextLen);
                            destroy(sessionKey, SESSION_KEY_LENGTH);
                            exit(1);
                        }
                    }
                    else if(!strncmp(token, "delete", strlen(token))) //delete fileName
                    {
                        if((token = strtok(NULL, " ")) == NULL) { cerr <<"Error in the command syntax"<<endl;}
                        string fileName(token);
                        memset(plaintext, 0, plaintextLen);
                        if(executeDelete(fileName, sessionKey, counterS, comm_socket, IDClient) < 0)
                        {
                            destroy(plaintext, plaintextLen);
                            destroy(sessionKey, SESSION_KEY_LENGTH);
                            exit(1);
                        }
                    }
                    else if(!strncmp(token, "logout", strlen(token)))
                    {
                        destroy(sessionKey, SESSION_KEY_LENGTH);
                        destroy(plaintext, plaintextLen);

                        cout << IDClient << " disconnected." << endl;
                        
                        break;
                    }                    
                }
            }
            exit(1);
        }
        close(comm_socket);
    }
    
    return 0;
}
