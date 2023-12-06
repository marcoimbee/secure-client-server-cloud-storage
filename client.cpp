/*
    GENERAL RULES
    -] All the int functions will return 3 possible values:
            If return 1, then it's all OK, so the caller continues its execution.
            If return 0, then it's a Tollerable-Error, so the caller continues its execution.
            If return -1, then it's a Critical-Error, so the caller stops its execution.
*/

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
#include <sstream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <bits/stdc++.h>
#include <math.h>

// ---------- DEFINES ----------
#define DIMACK 50
#define DIMMAX 2048
#define DIMTAG 16
#define DIMIV 16
#define KEYSIZE 2048
#define SHA256 256
#define SESSION_KEY_LENGTH EVP_CIPHER_key_length(EVP_aes_128_gcm())
#define ONEGB 1073741824
#define CHUNK_DIM 1048576UL // 1MB

using namespace std;

void deleteTempFile(string IDClient)
{
   remove( ("CLIENT_FILES/" + IDClient + "/tempPubk.pem").c_str() );
   remove( ("CLIENT_FILES/" + IDClient + "/certServer.pem").c_str() );
}

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

bool checkPort(const string& str1)
{
    if(str1.empty()){ cerr << "Error: port not allowed" << endl; return false; }

    static char ok_chars[] = "1234567890";

    if(str1.find_first_not_of(ok_chars) != string::npos) { cerr << "Error: port not allowed" << endl; return false; }
    
    return true;
}

bool sanification(const string& str1)
{
    if(str1.empty()){ cerr << "Error: invalid client ID" << endl; return false; }

    static char ok_chars[] = "abcdefghijklmnopqrstuvwxyz"
                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             "1234567890";

    if(str1.find_first_not_of(ok_chars) != string::npos) { cerr << "Error: invalid client ID" << endl; return false; }
    
    return true;
}

bool miaMalloc(unsigned char *&buffer, unsigned int len)
{
    buffer = (unsigned char *) malloc(len);
    if(!buffer){ cerr << "Error: miaMalloc() returned NULL" << endl; return false; }
    return true;
}

bool allocateANDgenerateIV(unsigned char *& iv, const EVP_CIPHER* cipher)
{
    if(!miaMalloc(iv, DIMIV))
        return false;
    RAND_poll();
   // Generate 16 bytes at random. That is my IV
    int ret = RAND_bytes((unsigned char*)&iv[0],DIMIV);
    if(ret!=1){
	      cerr <<"Error: RAND_bytes Failed\n";
          return false;
    }
    return true;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, unsigned long aad_len, unsigned char *tag,
                unsigned char *key, unsigned char *iv, int iv_len, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;
    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
    {
        EVP_CIPHER_CTX_cleanup(ctx);
        return -1;
    }
	//Provide any AAD data.
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

	//Provide the message to be decrypted, and obtain the plaintext output.
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        EVP_CIPHER_CTX_cleanup(ctx);
        return -1;
    }
        
    plaintext_len = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, DIMTAG, tag))
    {
        EVP_CIPHER_CTX_cleanup(ctx);
        return -1;
    }
        
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);
    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {        
        /* Verify failed */
        return -1;
    }
}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, unsigned long aad_len, unsigned char *key,
                unsigned char *iv, int iv_len, unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len = 0;
    //Creating and initialising the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        cerr << "Error: EVP_CIPHER_CTX_new failed" << endl;
        return -1;
    }

    //Initialising the encryption operation
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv))
    {
        cerr << "Error: EVP_EncryptInit failed" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    //Providing the AAD data
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        cerr << "Error: EVP_EncryptUpdate failed" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, iv, iv_len))
    {
        cerr << "Error: EVP_EncryptUpdate failed" << endl; 
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        cerr << "Error: EVP_EncryptUpdate failed" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len = len;
    
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
    {
        cerr << "Error: EVP_EncryptFinal failed" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    //Getting the TAG
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, DIMTAG, tag))
    {
        cerr << "Error: EVP_CIPHER_CTX_ctrl failed" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

bool write_file(unsigned char *path, unsigned char *buffer, unsigned long len)
{
    FILE *f = fopen((const char *)path, "w+");
    if(!f) { cerr << "Error opening the file '" << path << "'" << endl; return false; }
    if(fwrite(buffer, 1, len, f) != len){ cerr<<"Error while writing into file '" << path << "' (write_file function)" << endl; return false; }
    fclose(f);
    return true;
}

/*
    FORMAT OF M2: Ns, cert_dim, Cert_server, TempKpubS, (TempkpubS, Ns)signed_w_privkS
    The check_M2() function checks the correctness of message M2:
        -] validates the certificate received from the server by the CA Certificate.
        -] validates the signed Nonce by the server
*/
bool check_M2(unsigned char *M2, unsigned int Nc, unsigned int &Ns, string IDClient, unsigned char *certServer, long cert_dim, unsigned char* signature, unsigned char* tempPubk)
{
    bool check = true;
    
    if(! write_file( (unsigned char *)("CLIENT_FILES/" + IDClient + "/certServer.pem").c_str(), certServer, cert_dim ))
        return false;

    string CA_cert_filename = "CLIENT_FILES/" + IDClient + "/FoundationsOfCybersecurity_cert.pem";
    FILE *CA_cert_file = fopen(CA_cert_filename.c_str(), "r");
    if(!CA_cert_file){ cerr << "Error: can't open file" << endl; return false; }
    
    X509 *CA_cert = PEM_read_X509(CA_cert_file, NULL, NULL, NULL);
    fclose(CA_cert_file);
    if(!CA_cert) { cerr << "Error: PEM_read_X509 returned NULL" << endl; return false; }
    //LOADING THE CRL
    string CRL_filename = "CLIENT_FILES/" + IDClient + "/FoundationsOfCybersecurity_crl.pem";
    FILE *CRL_file = fopen(CRL_filename.c_str(), "r");
    if(!CA_cert_file) 
    {
        cerr << "Error: can't open file" << endl;
        return false;
    }
    X509_CRL *CRL = PEM_read_X509_CRL(CRL_file, NULL, NULL, NULL);
    fclose(CRL_file);
    if(!CRL) 
    {
        cerr << "Error: PEM_read_X509 returned NULL" << endl;
        return false;
    }
    
    //BUILDING A STORE WITH THE CA'S CERTIFICATE AND CRL
    X509_STORE *store = X509_STORE_new();
    if(!store) 
    {
        cerr << "Error: X509_STORE_new returned NULL" << endl;
        return false; 
    }
    check = X509_STORE_add_cert(store, CA_cert);
    if(!check) { cerr << "Error in X509_STORE_add_cert" << endl; return false; }
    check = X509_STORE_add_crl(store, CRL);
    if(!check) { cerr << "Error in X509_STORE_add_crl" << endl; return false; }
    check = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(!check) { cerr << "Error in X509_STORE_set_flags" << endl;  return false; }
    
    //LOADING THE CLIENT'S CERTIFICATE
    string certServer_file("CLIENT_FILES/" + IDClient + "/certServer.pem");
    FILE *cert_file = fopen(certServer_file.c_str(), "r");
    if(!cert_file) { cerr << "Error: can't open file" << endl; return false; }
    
    X509 *serverCert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if(!serverCert) { cerr << "Error: PEM_read_X509 returned NULL" << endl; return false; }
    
    //VERIFYING THE CERTIFICATE
    X509_STORE_CTX *cert_verify_ctx = X509_STORE_CTX_new();
    if(!cert_verify_ctx){ cerr << "Error: X_509_STORE_CTX returned NULL" << endl; return false; }
    
    check = X509_STORE_CTX_init(cert_verify_ctx, store, serverCert, NULL);
    if(!check) { cout << "Error in X509_STORE_CTX_init" << endl; return false; }
    
    check = X509_verify_cert(cert_verify_ctx);
    if(!check) { cout << "Error: Server's certificate has been revoked" << endl; return false; }
    
    unsigned char *clear_buf;
    unsigned int clear_size = KEYSIZE + sizeof(unsigned int);
    miaMalloc(clear_buf, clear_size); // [ TempkpubS || Nc ]
    //copying elements into the buffer
    memcpy(clear_buf, tempPubk, KEYSIZE);
    memcpy(clear_buf + KEYSIZE, &Nc, sizeof(unsigned int));
    
    write_file( (unsigned char *)("CLIENT_FILES/" + IDClient + "/tempPubk.pem").c_str(), tempPubk, strlen((char *)tempPubk) );
    
    //Extract server public key from certificate
    const EVP_MD* md = EVP_sha256();
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    int ret;
    if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; return false; }
    // verify the plaintext:
    ret = EVP_VerifyInit(md_ctx, md);
    if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; return false; }
    ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);  
    if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; return false; }
    ret = EVP_VerifyFinal(md_ctx, signature, SHA256, X509_get_pubkey(serverCert));
    if(ret == -1){  cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n"; return false; }
    else if(ret == 0){ cerr << "Error: Invalid signature!\n"; exit(1); }
    //write_file( (unsigned char *)("CLIENT_FILES/" + IDClient + "/certServer.pem").c_str(), certServer, cert_dim );
    
    destroy(clear_buf, clear_size);
    EVP_MD_CTX_free(md_ctx);
    X509_free(serverCert);
    X509_STORE_free(store);
    X509_STORE_CTX_free(cert_verify_ctx);
    return true;
}
                           
/*
    FORMAT M3: [ Ns, iv, encryptedSessionKLen, Enc(K, TempKpubS), encryptedK, (Ns)signed_w_privkC ]
    The buildM3() function builds the message M3:
        -] loads the client's private key
        -] signs the server's nonce called Ns
        -] builds the message M3
        -] return true if succeeds
        -] return false otherwise
*/
bool buildM3(unsigned char *M3, unsigned int Ns, unsigned char *encryptedSessionK, int encryptedSessionKLen, unsigned char *iv, unsigned int ivLen, unsigned char * encryptedK, int encryptedKLen, string IDClient)
{
    //Signature of Ns
    FILE *clientPrivKeyFile = fopen( ("CLIENT_FILES/" + IDClient + "/privk_" + IDClient + ".pem").c_str(), "r");
    if(!clientPrivKeyFile)
    {
        cerr << "Error: cannot open file client_privk.pem" << endl;
        return false;
    }
    EVP_PKEY *clientPrivKey = PEM_read_PrivateKey(clientPrivKeyFile, NULL, NULL, NULL);
    fclose(clientPrivKeyFile);
    if(!clientPrivKey)
    {
        cerr << "Error: PEM_read_PrivateKey clientPrivKey returned NULL" << endl;
        return false;
    }

    //      SIGNATURE of Ns
    const EVP_MD *md = EVP_sha256();
    //creating the signature context
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if(!md_ctx)
    {
        cerr << "Error: EVP_MD_CTX_new returned NULL" << endl;
        EVP_PKEY_free(clientPrivKey);
        return false;
    }
    //allocate the buffer for signature
    unsigned char* signature_buffer;
    if(!miaMalloc(signature_buffer, EVP_PKEY_size(clientPrivKey)))
    {
        EVP_PKEY_free(clientPrivKey);
        return false;
    }
    //allocating buffer to be signed
    unsigned char *buffer_to_sign;
    if(!miaMalloc(buffer_to_sign, sizeof(Ns) + encryptedSessionKLen))
    {   
        EVP_PKEY_free(clientPrivKey);
        return false;
    }
    memcpy(buffer_to_sign, &Ns, sizeof(Ns));
    memcpy(buffer_to_sign + sizeof(Ns), encryptedSessionK, encryptedSessionKLen);
    unsigned int signatureLen = SHA256;
    
    if(!EVP_SignInit(md_ctx, md)){cerr << "Error: EVP_SignInit returned 0" << endl; EVP_PKEY_free(clientPrivKey); return false; }
    if(!EVP_SignUpdate(md_ctx, buffer_to_sign, sizeof(Ns) + encryptedSessionKLen)){cerr << "Error: EVP_SignUpdate returned 0" << endl; EVP_PKEY_free(clientPrivKey); return false; }
    if(!EVP_SignFinal(md_ctx, signature_buffer, &signatureLen, clientPrivKey)){cerr << "Error: EVP_SignFinal returned 0" << endl; EVP_PKEY_free(clientPrivKey); return false; }
         
    //deleting the digest and the private key from memory
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(clientPrivKey);
    //   END   SIGNATURE of Ns --> In signature_buffer there is Ns signed by clientX
    
    memcpy(M3, iv, ivLen); 
    memcpy(M3 + ivLen, &encryptedSessionKLen, sizeof(encryptedSessionKLen));
    memcpy(M3 + ivLen + sizeof(encryptedSessionKLen) , encryptedSessionK, encryptedSessionKLen);
    memcpy(M3 + ivLen + sizeof(encryptedSessionKLen) + encryptedSessionKLen , encryptedK, encryptedKLen);
    memcpy(M3 + ivLen + sizeof(encryptedSessionKLen) + encryptedSessionKLen + encryptedKLen, signature_buffer, SHA256);
    
    return true;
}

/*
    check_counter() functions checks the alignment of two counters, counterC and counterS.
    In addition, check the wraparound of client's counter.
*/
bool check_counter(unsigned long counterS, unsigned long &counterC) 
{
    if(counterC == ULONG_MAX) 
    {
         cerr<<"Counter reached maximum value, the connection will be closed"<<endl;
         return false;
    }
    else if(counterC != counterS)
    {
        cerr<<"An attack has been detected, the connection will be closed"<<endl;
        return false;
    }
    counterC++;
    return true;
}

/*
    The checkACK() function verifies the ACK received by the server.
    It's used to understand the server's responce.
*/
int checkACK(int conn_socket, unsigned char *sessionKey, unsigned long &counterC, unsigned long *dimFile)
{
    unsigned char ackMsg[DIMMAX] = {0};
    if( recv(conn_socket, (void*)&ackMsg, DIMMAX, MSG_WAITALL) != DIMMAX ) { cerr<<"Error: recv checkACK"<<endl; return -1; }
    
    unsigned long counterS;
    memcpy(&counterS, ackMsg, sizeof(counterS));
    if(!check_counter(counterS, counterC))
        return -1;
    
    int ciphertextLen;
    memcpy(&ciphertextLen, ackMsg + sizeof(counterS), sizeof(ciphertextLen));
    unsigned char *ciphertext;
    if(!miaMalloc(ciphertext, ciphertextLen))
        return -1;
    memcpy(ciphertext, ackMsg + sizeof(counterS) + sizeof(ciphertextLen), ciphertextLen);
    
    unsigned char *iv, *tag_buf, *plaintext;;
    if(!miaMalloc(iv, DIMIV))
        return -1;
    if(!miaMalloc(tag_buf, DIMTAG))
        return -1;
    if(!miaMalloc(plaintext, DIMACK))
        return -1;
    memset(plaintext, '\0', DIMACK);
    memcpy(iv, ackMsg + sizeof(counterS) + sizeof(ciphertextLen) + ciphertextLen, DIMIV);
    memcpy(tag_buf, ackMsg + sizeof(counterS) + sizeof(ciphertextLen) + ciphertextLen + DIMIV, DIMTAG);
    
    int plaintextLen = gcm_decrypt(ciphertext, ciphertextLen, (unsigned char *)&counterS, sizeof(counterS), tag_buf, sessionKey, iv, DIMIV, plaintext);
    if( plaintextLen < 0) { cerr<<"Error while decrypting"<<endl; return -1; }
     
    string ACK ((char *)plaintext);
    char *token = strtok((char *)plaintext, "-");
    
    if (ACK.rfind("OK", 0) == 0) // if ACK starts with "OK" then ...
    { 
        if(dimFile != NULL) // if last parameter, that is dimFile, is != NULL ==> there is the size of downloading file in the ACK
        {
            if( (token = strtok(NULL, "-")) == NULL) { cout<<"Erorr receiving ACK from server"<<endl; return -1;}
            *dimFile = atol(token);
        }
        //if dimFile == NULL, then it's only an "OK MESSAGE"
        return 1;
    }
    
    if( (token = strtok(NULL, "-")) == NULL) { cout<<"Erorr receiving ACK from server"<<endl; return -1;}
    
    string msgFromServer(token);
    cout << "Error message from Server: " << msgFromServer <<endl;
        
    return 0;
}

/*
    The executeRename() function takes care to prepare the Rename-Request and sends it to server.
    It returns:
        -] 1 if the rename operation is confirmed by the server
        -] 0 if there is a Tollerable-Error and the server can't execute the rename operation (ex. the file specifies by client doesn't exists or the new fileName is invalid)
        -] -1 if there is an Non-tollerable error (ex. an recv error or malloc error)
*/
int executeRename(unsigned char *session_key, unsigned long &counterC, int conn_socket)
{
    string current_filename;
    string new_filename;
    int pt_len, ciphertextLen;
    unsigned char *iv;
	unsigned char *ciphertext;
	unsigned char *tag_buf;

    cout << "Type the name of the file that has to be renamed: ";
    cin >> current_filename;            //canonicalization + sanification SERVER SIDE
    if(!cin){ cerr << "Error Rename during input" << endl; return -1; }
    if(current_filename == "") { cout << "Please, enter a filename: "; return 0; }
    cout << "Type the new file name: ";
    cin >> new_filename;                //canonicalization + sanification SERVER SIDE
    if(!cin) { cerr << "Error Rename: during input" << endl; return -1; }
    if(new_filename == "") { cout << "Please, enter a filename: "; return 0; }

    string composed_command = "rename " + current_filename + " " + new_filename;
    pt_len = strlen(composed_command.c_str());

    if(!miaMalloc(ciphertext, pt_len+ EVP_CIPHER_block_size(EVP_aes_128_gcm())))
        return -1; // = (unsigned char*)malloc(pt_len + 16);
    if(!miaMalloc(tag_buf, DIMTAG))
        return -1; //tag_buf = (unsigned char *)malloc(DIMTAG);
    if(!allocateANDgenerateIV(iv, EVP_aes_128_gcm()))
        return -1;
    ciphertextLen = gcm_encrypt((unsigned char*)composed_command.c_str(), pt_len, (unsigned char *)&counterC, sizeof(unsigned long), session_key, iv, DIMIV, ciphertext, tag_buf);
    if(ciphertextLen < 0)
        return -1;
        
    // (counter | ciphertextlen | ciphertext | iv | tag)
    unsigned char to_be_sent[DIMMAX];
    memset(to_be_sent, '\0', DIMMAX);
    memcpy(to_be_sent, &counterC, sizeof(counterC));
    memcpy(to_be_sent + sizeof(counterC), &ciphertextLen, sizeof(ciphertextLen));
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen), ciphertext, ciphertextLen);
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen) + ciphertextLen, iv, DIMIV);
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen) + ciphertextLen + DIMIV, tag_buf, DIMTAG);
          
    if( send(conn_socket, (void*)to_be_sent, DIMMAX, MSG_WAITALL) != DIMMAX) { cerr<<"Error send executeRename()"<<endl; return -1; };
    counterC++;

    int retCheckACK = checkACK(conn_socket, session_key, counterC, NULL);
    
    if(retCheckACK == 1)
        cout<<"File renamed"<<endl;
    return retCheckACK;
}

/*
    The executeDelete() function takes care of prepare the Delete-Request and sends it to server
    It returns:
        -] 1  if the delete operation is confirmed by the server
        -] 0  if there is a Tollerable-Error and the server can't execute the delete operation (ex. the file specifies by client doesn't exists)
        -] -1 if there is a Non-Tollerable-Error (ex. an recv error or malloc error)
*/
int executeDelete(unsigned char *session_key, unsigned long &counterC, int conn_socket)
{
    int pt_len, ciphertextLen;
    unsigned char *iv;
	unsigned char *ciphertext;
	unsigned char *tag_buf;
    if(!miaMalloc(ciphertext, DIMMAX))
        return -1;
	if(!allocateANDgenerateIV(iv, EVP_aes_128_gcm()))
	    return -1;
	if(!miaMalloc(tag_buf, DIMTAG))
	    return -1;

    string filename;
    cout << "Type the name of the file that has to be deleted: ";
    cin >> filename;//canonicalization + sanification SERVER SIDE //delete cloud.pdf
    if(!cin){
        cerr << "Error during input" << endl;
        return -1;
    }
    if(filename == "")
    {
        cout<<"Please, enter a filename: ";
        return 0;
    }

    string composed_command = "delete " + filename;
    pt_len = strlen(composed_command.c_str());
    
    ciphertextLen = gcm_encrypt((unsigned char*)composed_command.c_str(), pt_len, (unsigned char *)&counterC, sizeof(unsigned long), session_key, iv, DIMIV, ciphertext, tag_buf);
    if(ciphertextLen < 0)
        return -1;
    // (counter | ciphertextlen | ciphertext | iv | tag)
    unsigned char to_be_sent[DIMMAX];
    memset(to_be_sent, '\0', DIMMAX);
    memcpy(to_be_sent, &counterC, sizeof(counterC));
    memcpy(to_be_sent + sizeof(counterC), &ciphertextLen, sizeof(ciphertextLen));
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen), ciphertext, ciphertextLen);
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen) + ciphertextLen, iv, DIMIV);
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen) + ciphertextLen + DIMIV, tag_buf, DIMTAG);

    if( send(conn_socket, (void*)to_be_sent, DIMMAX, MSG_WAITALL) != DIMMAX) { cerr<<"Error send executeDelete()"<<endl; return -1; };
    counterC++;

    int retCheckACK = checkACK(conn_socket, session_key, counterC, NULL);
    if(retCheckACK == 1)
        cout<<"File deleted"<<endl;
    return retCheckACK;
}

int executeList(unsigned char *session_key, unsigned long &counterC, int conn_socket)
{
    int pt_len, ciphertextLen;
    unsigned char *iv;
	unsigned char *ciphertext;
	unsigned char *tag_buf;
    string command = "list";
    pt_len = strlen( command.c_str() );
    ciphertext = (unsigned char*)malloc(pt_len + EVP_CIPHER_block_size(EVP_aes_128_gcm()));
    tag_buf = (unsigned char *)malloc(DIMTAG);
    if(!allocateANDgenerateIV(iv, EVP_aes_128_gcm()))
        return -1;
    ciphertextLen = gcm_encrypt((unsigned char*)command.c_str(), pt_len, (unsigned char *)&counterC, sizeof(unsigned long), session_key, iv, DIMIV, ciphertext, tag_buf);
    if(ciphertextLen < 0)
        return -1;
    // (counter | ciphertextlen | ciphertext | iv | tag)
    unsigned char to_be_sent[DIMMAX];
    memset(to_be_sent, '\0', DIMMAX);
    memcpy(to_be_sent, &counterC, sizeof(counterC));
    memcpy(to_be_sent + sizeof(counterC), &ciphertextLen, sizeof(ciphertextLen));
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen), ciphertext, ciphertextLen);
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen) + ciphertextLen, iv, DIMIV);
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen) + ciphertextLen + DIMIV, tag_buf, DIMTAG);

    if( send(conn_socket, (void*)to_be_sent, DIMMAX, MSG_WAITALL) != DIMMAX) { cerr<<"Error send executeList()"<<endl; return -1; };
    counterC++;

    unsigned char listMsg[DIMMAX] = {0};
    if( recv(conn_socket, (void*)&listMsg, DIMMAX, MSG_WAITALL) != DIMMAX ) { cerr<<"Error: recv listMsg"<<endl; return -1; } 
    
    unsigned long counterS;
    memcpy(&counterS, listMsg, sizeof(counterS));
    if(!check_counter(counterS, counterC))
        return -1;
    
    memcpy(&ciphertextLen, listMsg + sizeof(counterS), sizeof(ciphertextLen));
    if(!miaMalloc(ciphertext, ciphertextLen))
        return -1;
    memcpy(ciphertext, listMsg + sizeof(counterS) + sizeof(ciphertextLen), ciphertextLen);
    
    unsigned char* plaintext;
    if(!miaMalloc(plaintext, DIMMAX))
        return -1;
    if(!miaMalloc(iv, DIMIV))
        return -1;
    if(!miaMalloc(tag_buf, DIMTAG))
        return -1;
    memset(plaintext, '\0', DIMMAX);

    memcpy(iv, listMsg + sizeof(counterS) + sizeof(ciphertextLen) + ciphertextLen, DIMIV);
    memcpy(tag_buf, listMsg + sizeof(counterS) + sizeof(ciphertextLen) + ciphertextLen + DIMIV, DIMTAG);
    
    int plaintextLen = gcm_decrypt(ciphertext, ciphertextLen, (unsigned char *)&counterS, sizeof(counterS), tag_buf, session_key, iv, DIMIV, plaintext);
    if( plaintextLen < 0) { cerr<<"Decifratura fallita list"<<endl; return -1; }
    
    char *token = strtok((char *)plaintext, "|");
    cout<<"list --> [";
    while( (token = strtok(NULL, "|") ) != NULL)
    {
        cout<<token<<" | ";
    }   
    cout<<" ]"<<endl;
    return 1;
}

/*
    The extractFromMsgTheClearChunk() it's invoked in the Download operation.
    It takes care to extract the encrypted chunk from the Download-Message --> the function decrypts it --> and returns it to the caller.
    -] return true if suceeds and in addition, in the clear_chunk is stored the value of i-th chunk and in the clear_chunkLen variable is stored the lenght of clear_chunk.
    -] return false if a Non-Tollerable-Error occurs (ex malloc error or decrypt error)
*/
bool extractFromMsgTheClearChunk(unsigned char *downloadMsg, unsigned long &counterC, unsigned char *sessionKey, unsigned char *clear_chunk, int &clear_chunkLen)
{
    unsigned long counterS;
    unsigned char *encrypted_chunk;
    int encrypted_chunkLen;
    memcpy(&counterS, downloadMsg, sizeof(counterS));
    if(!check_counter(counterS, counterC))
        return false;
    
    unsigned char *iv, *tag_buf;
    if(!miaMalloc(iv, DIMIV))
        return false;
    if(!miaMalloc(tag_buf, DIMTAG))
        return false;
    memcpy(&encrypted_chunkLen, downloadMsg + sizeof(counterC), sizeof(encrypted_chunkLen));
    if(!miaMalloc(encrypted_chunk, encrypted_chunkLen))
        return false;
    
    memcpy(encrypted_chunk, downloadMsg + sizeof(counterC) + sizeof(encrypted_chunkLen), encrypted_chunkLen);
    memcpy(iv, downloadMsg + sizeof(counterC) + sizeof(encrypted_chunkLen) + encrypted_chunkLen, DIMIV);
    memcpy(tag_buf, downloadMsg + sizeof(counterC) + sizeof(encrypted_chunkLen) + encrypted_chunkLen + DIMIV, DIMTAG);
    
    clear_chunkLen = gcm_decrypt(encrypted_chunk, encrypted_chunkLen, (unsigned char *) &counterS, sizeof(counterS), tag_buf, sessionKey, iv, DIMIV, clear_chunk);
    if(clear_chunkLen < 0 )  { cerr<<"Decifratura fallita chunk "<<endl; return false; }
    
    return true;
}

int executeDownload(unsigned char *sessionKey, unsigned long &counterC, int conn_socket, string IDClient)
{
    unsigned char *iv;
	unsigned char *ciphertext; //this is the encrypted command
	unsigned char *tag_buf;
	if(!miaMalloc(ciphertext, DIMMAX))
	    return -1;
	if(!allocateANDgenerateIV(iv, EVP_aes_128_gcm()))
	    return -1;
	if(!miaMalloc(tag_buf, DIMTAG))
	    return -1;
	
    int pt_len, ciphertextLen;
    string fileName;//="video.mkv";// = "CloudComputingProject2022.pdf";//"open.cpp";//"project-conf.h";//"";
    cout << "Type the name of the file that you want to download: ";
    cin>>fileName;
    if(!cin){
        cerr << "Error during input" << endl;
        return -1;
    }
    if(fileName == "")
    {
        cout<<"Please, enter a filename: ";
        return 0;
    }
    unsigned long file_dim;
    
    string composed_command("download " + fileName); //send a msg to the server with the filename
    pt_len = strlen(composed_command.c_str());
    
    ciphertextLen = gcm_encrypt((unsigned char*)composed_command.c_str(), pt_len, (unsigned char *)&counterC, sizeof(unsigned long), sessionKey, iv, DIMIV, ciphertext, tag_buf);
    if(ciphertextLen < 0)
	    return -1;
    unsigned char to_be_sent[DIMMAX] = {0};
    memcpy(to_be_sent, &counterC, sizeof(counterC));
    memcpy(to_be_sent + sizeof(counterC), &ciphertextLen, sizeof(ciphertextLen));
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen), ciphertext, ciphertextLen);
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen) + ciphertextLen, iv, DIMIV);
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen) + ciphertextLen + DIMIV, tag_buf, DIMTAG);

    // Download-Request --> [ counterC || ciphertextLen || {"download nomeFile"}session_key || iv || tag ]
    if( send(conn_socket, (void*)to_be_sent, DIMMAX, MSG_WAITALL) != DIMMAX) { cerr<<"Error send executeUpload()"<<endl; return -1; }
    counterC++;
    
    // Download-Reply --> [ counterS || ciphertextLen || {"OK nomeFile dimFile"}session_key || iv || tag]
    unsigned long dimFile;
    int retCheckACK = checkACK(conn_socket, sessionKey, counterC, &dimFile);
    if(retCheckACK <= 0)
        return retCheckACK;
    
    //If the file already exists on client side, it will be deleted.
    FILE *downloadedFile = fopen( ("CLIENT_FILES/" + IDClient + "/" + fileName).c_str(), "r");
    if(downloadedFile)
        remove(("CLIENT_FILES/" + IDClient + "/" + fileName).c_str());
        
    downloadedFile = fopen( ("CLIENT_FILES/" + IDClient + "/" + fileName).c_str(), "ab");
    if(!downloadedFile) { cerr<<"Error: can't open file"<<endl; return -1; }
    
    unsigned int tot_chunks = floor(dimFile / CHUNK_DIM);
    cout<<"Downloading " << tot_chunks + 1 << " chunks from server ..."<< endl;
    cout<<"[";
    unsigned char clear_chunk[CHUNK_DIM] = {0};
    unsigned char downloadMsg[CHUNK_DIM + DIMMAX] = {0};
    int encrypted_chunkLen, clear_chunkLen;
    for(unsigned int i = 0; i < tot_chunks; i++)
    {
        if( ( recv(conn_socket, (void*)&downloadMsg, CHUNK_DIM + DIMMAX, MSG_WAITALL) ) != ( CHUNK_DIM + DIMMAX) ) { cerr<<"Error recv download nel ciclo"<<endl; return -1; }
        
        if(!extractFromMsgTheClearChunk(downloadMsg, counterC, sessionKey, clear_chunk, clear_chunkLen))
            return -1;
        if( fwrite(clear_chunk, 1, clear_chunkLen, downloadedFile) != clear_chunkLen) { cerr<<"Error fwrite chunk "<<i<<endl; return -1; }
        memset(&downloadMsg, 0, CHUNK_DIM + DIMMAX);
        cout<<".";
    }
    
    unsigned int remeaningByte = dimFile - (CHUNK_DIM*tot_chunks);
    if(remeaningByte != 0)
    {
        if(tot_chunks == 0)
             cout<<"Waiting " << remeaningByte << " bytes from server "<< endl;
        if( recv(conn_socket, (void*)&downloadMsg, (CHUNK_DIM + DIMMAX) ,MSG_WAITALL ) != (CHUNK_DIM + DIMMAX)) // No Wraparound possible
        { cerr<<"Error recv download remeaningByte "<<endl; return -1; }
        
        if(!extractFromMsgTheClearChunk(downloadMsg, counterC, sessionKey, clear_chunk, clear_chunkLen))
            return -1;
        
        if( fwrite(clear_chunk, 1, clear_chunkLen, downloadedFile) != clear_chunkLen) { cerr<<"Error fwrite file "<<fileName<<endl; return -1;}
        if(tot_chunks == 0)
            cout<<".";
    }
    
    cout<<"]"<<endl<<"Download completed"<<endl;
    fclose(downloadedFile);
    return 1;
}

/*
    The builUploadMessage() function build the Upload-Message that contain the encrypted chunk, so it isn't the Upload-Request.
    See the Upload-Message format.
*/
void builUploadMessage(unsigned char *uploadMsg, unsigned long counterC, int encrypted_chunkLen, unsigned char *encrypted_chunk, unsigned char *iv, unsigned char *tag_buf)
{
    memcpy(uploadMsg, &counterC, sizeof(counterC));
    memcpy(uploadMsg + sizeof(counterC), &encrypted_chunkLen, sizeof(encrypted_chunkLen));
    memcpy(uploadMsg + sizeof(counterC) + sizeof(encrypted_chunkLen), encrypted_chunk, encrypted_chunkLen);
    memcpy(uploadMsg + sizeof(counterC) + sizeof(encrypted_chunkLen) + encrypted_chunkLen, iv, DIMIV);
    memcpy(uploadMsg + sizeof(counterC) + sizeof(encrypted_chunkLen) + encrypted_chunkLen + DIMIV, tag_buf, DIMTAG);
}

/*
    The encryptChunk() function it's invoked in the Upload-Operation to encrypt the i-th chunk of uploading file.
    This function takes care to encrypt the passed chunk  return it in the encrypted_chunk variable and its lenght in the encrypted_chunkLen variable.
*/
bool encryptChunk(unsigned char *chunk, unsigned int chunkLen, unsigned long counterC, unsigned char *session_key, unsigned char *encrypted_chunk, int &encrypted_chunkLen, unsigned char * iv, unsigned char * tag_buf)
{   
	memset(encrypted_chunk, '\0', CHUNK_DIM + (DIMMAX/2));
    encrypted_chunkLen = gcm_encrypt(chunk, chunkLen, (unsigned char *)&counterC, sizeof(unsigned long), session_key, iv, DIMIV, encrypted_chunk, tag_buf);
    if(encrypted_chunkLen < 0)
        return false;
    return true;
}

int executeUpload(unsigned char *session_key, unsigned long &counterC, int conn_socket, string IDClient)
{
    unsigned char *iv;
	unsigned char *ciphertext;
	unsigned char *tag_buf;
	if(!miaMalloc(ciphertext, DIMMAX))
	    return -1;
	if(!allocateANDgenerateIV(iv, EVP_aes_128_gcm()))
	    return -1;
	if(!miaMalloc(tag_buf, DIMTAG))
	    return -1;
	
    int pt_len, ciphertextLen;
    string filename;
    cout << "Type the name of the file that you want to upload: ";
    cin>>filename;
    if(!cin){
        cerr << "Error during input" << endl;
        return -1;
    }
    if(filename == "")
    {
        cout<<"Please, enter a filename: ";
        return 0;
    }
    
    unsigned long file_dim;
    FILE * to_be_uploaded = fopen( ("CLIENT_FILES/" + IDClient + "/" + filename).c_str(), "rb");
    if(!to_be_uploaded){  cerr << "Error: the chosen file doesn't exist." << endl; return 0; }
    //getting the file dimension -> if > than 4GB then abort operation
    fseek(to_be_uploaded, 0, SEEK_END);
    file_dim = ftell(to_be_uploaded);
    fseek(to_be_uploaded, 0, SEEK_SET);

    if(file_dim > (4UL * ONEGB)) { cerr << "Error: unable to upload files bigger than 4GB." << endl; return 0; }
    
    string composed_command("upload " + filename + " " + to_string(file_dim));
    //send a msg to the server with the filename
    pt_len = strlen(composed_command.c_str());
    ciphertextLen = gcm_encrypt((unsigned char*)composed_command.c_str(), pt_len, (unsigned char *)&counterC, sizeof(unsigned long), session_key, iv, DIMIV, ciphertext, tag_buf);
    if(ciphertextLen < 0)
        return -1;
    unsigned char to_be_sent[DIMMAX] = {0};
    memcpy(to_be_sent, &counterC, sizeof(counterC));
    memcpy(to_be_sent + sizeof(counterC), &ciphertextLen, sizeof(ciphertextLen));
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen), ciphertext, ciphertextLen);
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen) + ciphertextLen, iv, DIMIV);
    memcpy(to_be_sent + sizeof(counterC) + sizeof(ciphertextLen) + ciphertextLen + DIMIV, tag_buf, DIMTAG);

    if( send(conn_socket, (void*)to_be_sent, DIMMAX, MSG_WAITALL) != DIMMAX) { cerr<<"Error send executeUpload()"<<endl; return -1; }
    counterC++;
    
    int retCheckACK = checkACK(conn_socket, session_key, counterC, NULL);
    if(retCheckACK <= 0)
        return retCheckACK;
    
    unsigned char chunk[CHUNK_DIM]; // chunk[1MB];
    //counting the # of chunks that we need to send
    unsigned int tot_chunks = floor(file_dim / CHUNK_DIM);
    
    cout<<"Uploading " << tot_chunks + 1 << " chunks ... " << endl;
    cout<<"[";
    unsigned char encrypted_chunk[CHUNK_DIM + (DIMMAX/2)];
    unsigned char uploadMsg[CHUNK_DIM + DIMMAX] = {0};
    
    int encrypted_chunkLen;
    for(unsigned int i = 0; i < tot_chunks; i++)
    {
        free(iv); 
        if(!allocateANDgenerateIV(iv, EVP_aes_128_gcm()))
            return -1;
        
        fread(&chunk, 1, CHUNK_DIM, to_be_uploaded);  //lettura dei chunk di dimensione CHUNK_DIM   

        if(!encryptChunk(chunk, CHUNK_DIM, counterC, session_key, encrypted_chunk, encrypted_chunkLen, iv, tag_buf))
            return -1;
        builUploadMessage(uploadMsg, counterC, encrypted_chunkLen, encrypted_chunk, iv, tag_buf);
        
        if( send(conn_socket, (void*)uploadMsg, CHUNK_DIM + DIMMAX, MSG_WAITALL) != (CHUNK_DIM + DIMMAX )) { cerr<<"Error send executeUpload()"<<endl; return -1; }
        counterC++;
        cout<<".";
    }
    
    memset(&chunk, 0, CHUNK_DIM);
    unsigned int byteToRead = file_dim - (CHUNK_DIM*tot_chunks);
    if(byteToRead != 0)
    {
        free(iv);
        if(!allocateANDgenerateIV(iv, EVP_aes_128_gcm()))
            return -1;
        
        fread(&chunk, 1, byteToRead, to_be_uploaded);
        if(!encryptChunk(chunk, byteToRead, counterC, session_key, encrypted_chunk, encrypted_chunkLen, iv, tag_buf))
            return -1;
        builUploadMessage(uploadMsg, counterC, encrypted_chunkLen, encrypted_chunk, iv, tag_buf);
        
        if( send(conn_socket, (void*)uploadMsg, CHUNK_DIM + DIMMAX, MSG_WAITALL) != (CHUNK_DIM + DIMMAX )) { cerr<<"Error send executeUpload()"<<endl; return -1; }
        counterC++;
        if(tot_chunks == 0)
        cout<<".";
    }
    cout<<"]"<<endl<<"Upload completed"<<endl;
    fclose(to_be_uploaded);
    return 1;

}
int executeLogout(unsigned char *&session_key, unsigned long &counterC, int conn_socket)
{
    unsigned char LogOutMsg[DIMMAX] = {0};
    string plaintext = "logout";
    int plaintextLen = plaintext.length();
    unsigned char *iv;
	unsigned char *ciphertext;
	unsigned char *tag_buf;
	int ciphertextLen;

    /* Sending msg to the server for disconnecting */
	if(!miaMalloc(ciphertext, plaintextLen + EVP_CIPHER_block_size(EVP_aes_128_gcm())))
	    return -1;
	if(!allocateANDgenerateIV(iv, EVP_aes_128_gcm()))
	    return -1;
	if(!miaMalloc(tag_buf, DIMTAG))
	    return -1;
	
	ciphertextLen = gcm_encrypt((unsigned char*)plaintext.c_str(), plaintextLen, (unsigned char *)&counterC, sizeof(counterC), session_key, iv, DIMIV, ciphertext, tag_buf);
	if(ciphertextLen < 0)
	    return -1;
	memcpy(LogOutMsg, &counterC, sizeof(counterC));
    memcpy(LogOutMsg + sizeof(counterC), &ciphertextLen, sizeof(ciphertextLen));
    memcpy(LogOutMsg + sizeof(counterC) + sizeof(ciphertextLen), ciphertext, ciphertextLen);
    memcpy(LogOutMsg + sizeof(counterC) + sizeof(ciphertextLen) + ciphertextLen, iv, DIMIV);
    memcpy(LogOutMsg + sizeof(counterC) + sizeof(ciphertextLen) + ciphertextLen + DIMIV, tag_buf, DIMTAG);
    
    if( send(conn_socket, (void*)LogOutMsg, DIMMAX, MSG_WAITALL) != DIMMAX) { cerr<<"Error sending LogOutMsg"<<endl; return -1; }
    counterC++;
   
    cout<<"Client disconnected, bye."<<endl;
    /* deallocating sensible data */
    free(iv);
    free(ciphertext);
    free(tag_buf);
    
    return 1;
}

int main(int argc, char* argv[])
{
   int port;
   uint32_t client_port;
   struct sockaddr_in server_address;
   int conn_socket;
   uint16_t msg_len;
   int len;
   int check;

   if(argv[1] != NULL && argv[2] != NULL && checkPort(argv[1]))
       client_port = atoi(argv[1]);
   else
   {
       cerr<<"Argument problem!"<<endl;
       exit(1);
   }
   //check arg[2] not tainted
   if(!sanification(argv[2]))
       exit(1);
   string IDClient(argv[2]);
   transform(IDClient.begin(), IDClient.end(), IDClient.begin(), ::tolower); //IDClient is only in lowecase!
   
   
   conn_socket = socket(AF_INET, SOCK_STREAM, 0);
   memset(&server_address, 0, sizeof(server_address));
   server_address.sin_family = AF_INET;
   server_address.sin_port = htons(4242);
   inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr);
   check = connect(conn_socket, (struct sockaddr*)&server_address, sizeof(server_address));
   cout<<"CLIENT: connected to server"<<endl;
    
   /*  ******************************************** START KEY ESTABLISHMENT ******************************************** */
   RAND_poll();
   unsigned int Nc;
   unsigned int Ns;
   
   
   if ( RAND_bytes((unsigned char*)&Nc, sizeof(Nc)) != 1) { cerr <<"Error: RAND_bytes Failed\n"; exit(1); }
   unsigned char M1[DIMMAX]; 
   memset(M1, '\0', DIMMAX);
   /* Building of message M1 */ 
   memcpy(M1, &Nc, sizeof(Nc));
   memcpy(M1 + sizeof(Nc), IDClient.c_str(), IDClient.length());
    
   if( send(conn_socket, (void*)M1, DIMMAX, MSG_WAITALL) != DIMMAX) { cerr <<"Error: send Nc\n"; exit(1); }
    
   unsigned char M2[2*DIMMAX];
   memset(M2, '\0', 2*DIMMAX);
    
   if( recv(conn_socket, (void*)&M2, 2*DIMMAX, MSG_WAITALL) == -1 ) { cerr<<"Error: recv "<<endl; exit(1); } 
    
   long cert_dim;
   unsigned char tempPubk[KEYSIZE];
   unsigned char signature[SHA256];
   
   /*  Extracting data from encoming M2 */
   memcpy(&Ns, M2, sizeof(unsigned int));
   memcpy(&cert_dim, M2 + sizeof(unsigned int) , sizeof(long));

   unsigned char certServer[cert_dim];
   memcpy(certServer, M2 + sizeof(unsigned int) + sizeof(long) , cert_dim);
   memcpy(tempPubk, M2 + sizeof(unsigned int) + sizeof(long) + cert_dim , KEYSIZE);
   memcpy(signature, M2 + sizeof(unsigned int) + sizeof(long) + cert_dim + KEYSIZE, SHA256);

    
    // Check the message M2
   if(!check_M2(M2, Nc, Ns, IDClient, certServer, cert_dim, signature, tempPubk))
       exit(1);
       
   //Writing server certificate on client side
   unsigned char * session_key;
   if(!miaMalloc(session_key, SESSION_KEY_LENGTH))
       exit(1);
   RAND_poll();
   
   int ret = RAND_bytes((unsigned char*)&session_key[0],SESSION_KEY_LENGTH); // Choose of Random Session Key
   if(ret!=1) { cerr <<"Error: RAND_bytes Failed\n"; exit(1); }

    // load the peer's public key:
   FILE* pubkey_file = fopen(("CLIENT_FILES/" + IDClient + "/tempPubk.pem").c_str(), "r");
   if(!pubkey_file){ cerr << "Error: cannot open file tempPubk.pem (missing?)\n"; exit(1); }
   EVP_PKEY* tempPubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
   fclose(pubkey_file);
   if(!tempPubkey){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }

   const EVP_CIPHER* cipher = EVP_aes_128_cbc();
   int encrypted_key_len = EVP_PKEY_size(tempPubkey);
   int iv_len = EVP_CIPHER_iv_length(cipher);
   int block_size = EVP_CIPHER_block_size(cipher);

    // create the envelope context
   EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
   if(!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; EVP_PKEY_free(tempPubkey); exit(1); }

   // allocate buffers for encrypted key and IV:
   unsigned char* encrypted_key , *envelope_iv ;
   if( (!miaMalloc(encrypted_key, encrypted_key_len)) || (!miaMalloc(envelope_iv, iv_len)) )
   {
        cerr << "Error: malloc returned NULL (encrypted key too big?)"<<endl;
        EVP_PKEY_free(tempPubkey); 
        exit(1);
   }
   
   //Check overflow (SESSION_KEY_LENGTH + block_size)
   if(SESSION_KEY_LENGTH > INT_MAX - block_size) { cerr <<"Error: integer overflow (file too big?)\n"; EVP_PKEY_free(tempPubkey);  exit(1); }
   int enc_buffer_size = SESSION_KEY_LENGTH + block_size;
   unsigned char* ciphertext_envelope;
   if(!miaMalloc(ciphertext_envelope, enc_buffer_size))
   {
       EVP_PKEY_free(tempPubkey); 
       exit(1);
   }
   if(!ciphertext_envelope) { cerr << "Error: malloc returned NULL (file too big?)\n"; EVP_PKEY_free(tempPubkey); exit(1); }

   ret = EVP_SealInit(ctx, cipher, &encrypted_key, &encrypted_key_len, envelope_iv, &tempPubkey, 1);
   if(ret <= 0){  cerr <<"Error: EVP_SealInit returned " << ret <<"\n"; EVP_PKEY_free(tempPubkey); exit(1); }
   int lenEnvelope = 0; // bytes encrypted at each chunk
   int lentot = 0; // total encrypted bytes
   ret = EVP_SealUpdate(ctx, ciphertext_envelope, &lenEnvelope, session_key, SESSION_KEY_LENGTH);  
   if(ret == 0)
   {
        cerr << "Error: EVP_SealUpdate returned " << ret << endl;
        EVP_PKEY_free(tempPubkey); EVP_CIPHER_CTX_free(ctx);
        deleteTempFile(IDClient);
        exit(1);
   }
   lentot += lenEnvelope;
   ret = EVP_SealFinal(ctx, ciphertext_envelope + lentot, &lenEnvelope);
   if(ret == 0)
   {
        cerr << "Error: EVP_SealFinal returned " << ret << endl;
        EVP_PKEY_free(tempPubkey);
        EVP_CIPHER_CTX_free(ctx);
        deleteTempFile(IDClient);
        exit(1);
   }
   lentot += lenEnvelope;
   
   // delete the context and the plaintext from memory:
   EVP_CIPHER_CTX_free(ctx);
   
   //In ciphertext_envelope there is the Session K entrypted with tempPubKey and iv
   unsigned char M3[DIMMAX] = {0};
   
   if(!buildM3(M3, Ns, ciphertext_envelope, lentot,  envelope_iv, EVP_CIPHER_iv_length(cipher), encrypted_key, encrypted_key_len, IDClient))
        free(session_key);
   deleteTempFile(IDClient);
   if( send(conn_socket, (void*)M3, DIMMAX, MSG_WAITALL) != DIMMAX) 
   {
        cerr <<"Error: send M3\n";
        free(session_key);
   }
    
    //DEALLOCATING CRITICAL VARIABLES
   free(encrypted_key);
   free(ciphertext_envelope);
   free(envelope_iv);
   deleteTempFile(IDClient);
   
   //BIO_dump_fp (stdout, (const char *)session_key, SESSION_KEY_LENGTH);
   
    unsigned long counterC = 0;
    unsigned long counterS = 0;
    
    while(true)
    {
        bool menu_ok = false;

        string command;
        cout <<endl<< "Type one of the following options:" << endl;
        cout << "> Upload: spcifies a filename on your device and sends it to the server (max size 4GB)" << endl;
        cout << "> Download: specifies a file on the server and downloads it to your device" << endl;
        cout << "> Delete: specifies a file on the server and deletes it" << endl;
        cout << "> List: shows a list of the available files on the server" << endl;
        cout << "> Rename: specifies a file on the server and renames it" << endl;
        cout << "> LogOut: closes the connection with the server" << endl;
        //cin.ignore('\n');
	    while(!menu_ok)
	    {
            cin >> command;
            transform(command.begin(), command.end(), command.begin(), ::tolower);
            if(command == "upload" || command == "download" || command == "delete" || command == "list" || command == "rename" || command == "logout"){
                menu_ok = true;
            }else{
                cout << "Type one of the showed options" << endl;
                menu_ok = false;
            }
        }
    
        //----- UPLOAD -----
        if(command == "upload")
        {
            if(executeUpload(session_key, counterC, conn_socket, IDClient) < 0)
            {
                destroy(session_key, SESSION_KEY_LENGTH);
                exit(1);
            }
        }

        //----- DOWNLOAD -----
        else if(command == "download"){
            if(executeDownload(session_key, counterC, conn_socket, IDClient) < 0)
            {
                destroy(session_key, SESSION_KEY_LENGTH);
                exit(1);
            }
        }

        //----- DELETE -----
        else if(command == "delete" ){
            if( executeDelete(session_key, counterC, conn_socket) < 0)
            {
                destroy(session_key, SESSION_KEY_LENGTH);
                exit(1);
            }
        }

        //----- LIST -----
        else if(command == "list" )
        {
            if(executeList(session_key, counterC, conn_socket) < 0)
            {
                destroy(session_key, SESSION_KEY_LENGTH);
                exit(1);
            }
        }

        //----- RENAME -----
        else if(command == "rename" )
        {
            if(executeRename(session_key, counterC, conn_socket) < 0)
            {
                destroy(session_key, SESSION_KEY_LENGTH);
                exit(1);
            }
        }

        //----- LOGOUT -----
        else if(command == "logout" )
        {
            if(executeLogout(session_key, counterC, conn_socket) < 0)
            {
                destroy(session_key, SESSION_KEY_LENGTH);
                exit(1);
            }
            break;
        }
    }
    close(conn_socket);
    return 0;
}
