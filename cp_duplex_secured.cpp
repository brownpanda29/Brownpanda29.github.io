#include <iostream>
#include <thread>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <unistd.h>
#include <arpa/inet.h>

// Fixed port for both peers
#define PORT 12345

// Function to generate ECDH Curve25519 key pair
EVP_PKEY* generate_ecdh_key() {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;

    // Create context for ECDH key generation
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) {
        std::cerr << "Error creating EVP_PKEY_CTX" << std::endl;
        return nullptr;
    }

    // Generate the ECDH key pair
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Error initializing ECDH keygen" << std::endl;
        return nullptr;
    }

    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        std::cerr << "Error generating ECDH key" << std::endl;
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return key;
}

// Function to derive shared secret
unsigned char* derive_shared_secret(EVP_PKEY *private_key, EVP_PKEY *peer_public_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    unsigned char *shared_secret = nullptr;
    size_t secret_len = 0;

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        std::cerr << "Error initializing ECDH derive" << std::endl;
        return nullptr;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_public_key) <= 0) {
        std::cerr << "Error setting peer public key" << std::endl;
        return nullptr;
    }

    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
        std::cerr << "Error getting shared secret length" << std::endl;
        return nullptr;
    }

    shared_secret = (unsigned char*)malloc(secret_len);
    if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0) {
        std::cerr << "Error deriving shared secret" << std::endl;
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return shared_secret;
}

// AES-256 encryption
void aes_encrypt(const unsigned char *key, const unsigned char *plaintext, unsigned char *ciphertext, int &ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char iv[16] = {0};  // AES CBC mode requires an initialization vector

    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, strlen((char*)plaintext));
    int len;
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

// AES-256 decryption
void aes_decrypt(const unsigned char *key, const unsigned char *ciphertext, unsigned char *plaintext, int ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char iv[16] = {0};  // Initialization vector

    EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
    int len;
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    int plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext[plaintext_len] = '\0';  // Null-terminate the decrypted message
}

// Function to handle sending and receiving messages
void send_message(int sockfd, unsigned char *shared_secret) {
    std::string message;
    unsigned char ciphertext[1024];
    int ciphertext_len;

    while (true) {
        std::getline(std::cin, message);

        // Encrypt the message using the shared secret
        aes_encrypt(shared_secret, (unsigned char*)message.c_str(), ciphertext, ciphertext_len);

        send(sockfd, ciphertext, ciphertext_len, 0);  // Send encrypted message
    }
}

void receive_message(int sockfd, unsigned char *shared_secret) {
    unsigned char buffer[1024];
    unsigned char decrypted_message[1024];
    int len;

    while (true) {
        len = recv(sockfd, buffer, sizeof(buffer), 0);  // Receive encrypted message

        if (len <= 0) break;

        // Decrypt the message using the shared secret
        aes_decrypt(shared_secret, buffer, decrypted_message, len);

        std::cout << "Received: " << decrypted_message << std::endl;
    }
}

// Peer A (Server)
void peer_a(const std::string &peer_ip) {
    int sockfd, newsockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error opening socket\n";
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Error binding\n";
        return;
    }

    listen(sockfd, 5);
    std::cout << "Waiting for connection from Peer B...\n";

    newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (newsockfd < 0) {
        std::cerr << "Error on accept\n";
        return;
    }

    std::cout << "Connected to Peer B\n";

    // Generate ECDH key pair for Peer A
    EVP_PKEY *peer_a_key = generate_ecdh_key();

    // Receive public key from Peer B
    unsigned char peer_b_pub_key[32];
    recv(newsockfd, peer_b_pub_key, sizeof(peer_b_pub_key), 0);

    // Derive shared secret using Peer A's private key and Peer B's public key
    EVP_PKEY *peer_b_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_b_pub_key, 32);
    unsigned char *shared_secret = derive_shared_secret(peer_a_key, peer_b_key);

    // Send Peer A's public key to Peer B
    unsigned char peer_a_pub_key[32];
    size_t pub_key_len;
    EVP_PKEY_get_raw_public_key(peer_a_key, peer_a_pub_key, &pub_key_len);
    send(newsockfd, peer_a_pub_key, pub_key_len, 0);

    // Start send/receive message threads
    std::thread send_thread(send_message, newsockfd, shared_secret);
    std::thread receive_thread(receive_message, newsockfd, shared_secret);

    send_thread.join();
    receive_thread.join();

    close(newsockfd);
    close(sockfd);
}

// Peer B (Client)
void peer_b(const std::string &peer_ip) {
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error opening socket\n";
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(peer_ip.c_str());

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Error connecting\n";
        return;
    }

    std::cout << "Connected to Peer A\n";

    // Generate ECDH key pair for Peer B
    EVP_PKEY *peer_b_key = generate_ecdh_key();

    // Send Peer B's public key to Peer A
    unsigned char peer_b_pub_key[32];
    size_t pub_key_len;
    EVP_PKEY_get_raw_public_key(peer_b_key, peer_b_pub_key, &pub_key_len);
    send(sockfd, peer_b_pub_key, pub_key_len, 0);

    // Receive Peer A's public key
    unsigned char peer_a_pub_key[32];
    recv(sockfd, peer_a_pub_key, sizeof(peer_a_pub_key), 0);

    // Derive shared secret using Peer B's private key and Peer A's public key
    EVP_PKEY *peer_a_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_a_pub_key, 32);
    unsigned char *shared_secret = derive_shared_secret(peer_b_key, peer_a_key);

    // Start send/receive message threads
    std::thread send_thread(send_message, sockfd, shared_secret);
    std::thread receive_thread(receive_message, sockfd, shared_secret);

    send_thread.join();
    receive_thread.join();

    close(sockfd);
}

int main() {
    std::string peer_ip;
    std::cout << "Enter the IP address of the peer (Peer A or Peer B): ";
    std::cin >> peer_ip;

    int choice;
    std::cout << "Enter 1 for Peer A (Server), 2 for Peer B (Client): ";
    std::cin >> choice;

    if (choice == 1) {
        peer_a(peer_ip);  // Run as Peer A (Server)
    } else if (choice == 2) {
        peer_b(peer_ip);  // Run as Peer B (Client)
    } else {
        std::cerr << "Invalid choice\n";
    }

    return 0;
}
