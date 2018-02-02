#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <gcrypt.h>

/*
* code from https://github.com/vedantk/gcrypt-example
*/

void initialize(){
    gcry_error_t err = 0;
    
    if (!gcry_check_version(GCRYPT_VERSION)){
        printf("gcrypt version is mismatched.\n");
        exit(1);
    }
    err |= gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    err |= gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    
    if (err){
        printf("there is an error in gcrypt initialization.\n");
        exit(1);
    }
}

void loadkey(gcry_sexp_t *kp){
    FILE *fp = fopen("./key", "rb");
    if(fp == NULL){
        printf("cannot open the key file.\n");
        exit(1);
    }
    
    size_t file_len;
    fseek(fp, 0, SEEK_END);
    file_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    void *elgamal_buf = malloc(512 / 8 * 1024);
    if(elgamal_buf == NULL){
        printf("failed to allocate the space to store the key.\n");
        exit(1);
    }

    fread(elgamal_buf, 1, file_len, fp);
    fclose(fp);
    
    size_t error_offset = -1;
    gcry_sexp_sscan(kp, &error_offset, elgamal_buf, file_len);
    if(error_offset != -1){
        printf("failed to load the key.\n");
        exit(1);
    }
    free(elgamal_buf);
}

void encrypt(gcry_sexp_t *kp){
    gcry_error_t err = 0;
    FILE *fp = fopen("./pt", "rb");
    if(fp == NULL){
        printf("cannot open the plaintext file.\n");
        exit(1);
    }
    
    size_t file_len;
    fseek(fp, 0, SEEK_END);
    file_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *pt_buf = malloc(512 / 8 * 1024);
    memset(pt_buf, 0, 512 / 8 * 1024);
    if(pt_buf == NULL){
        printf("failed to allocate the space to store the plaintext.\n");
        exit(1);
    }
    fread(pt_buf, 1, file_len, fp);
    fclose(fp);

    gcry_mpi_t plaintext = gcry_mpi_new(1024);
    err = gcry_mpi_scan(&plaintext, GCRYMPI_FMT_HEX, pt_buf, 0, NULL);
    if(err){
        printf("failed to parse the plaintext.\n");
        exit(1);
    }

    gcry_sexp_t plaintext_exp;
    err = gcry_sexp_build(&plaintext_exp, NULL,
                           "(data (flags raw) (value %M))", plaintext);
    if(err){
        printf("failed to load the plaintext.\n");
        exit(1);
    }

    gcry_sexp_t ciphertext_exp;
    err = gcry_pk_encrypt(&ciphertext_exp, plaintext_exp, *kp);
    if(err){
        printf("failed to encrypt.\n");
        exit(1);
    }
    
    gcry_sexp_t elgamal_a_exp = gcry_sexp_find_token(ciphertext_exp, "a", 1);
    gcry_sexp_t elgamal_b_exp = gcry_sexp_find_token(ciphertext_exp, "b", 1);
    
    gcry_mpi_t elgamal_a = gcry_mpi_new(1024);
    gcry_sexp_extract_param(elgamal_a_exp, NULL, "a", &elgamal_a, NULL);
    
    gcry_mpi_t elgamal_b = gcry_mpi_new(1024);
    gcry_sexp_extract_param(elgamal_b_exp, NULL, "b", &elgamal_b, NULL);
    
    void *elgamal_a_str = malloc(512 / 8 * 1024);
    if(elgamal_a_str == NULL){
        printf("failed to allocate the space to store the ciphertext.\n");
        exit(1);
    }
    
    void *elgamal_b_str = malloc(512 / 8 * 1024);
    if(elgamal_b_str == NULL){
        printf("failed to allocate the space to store the ciphertext.\n");
        exit(1);
    }
    
    err = gcry_mpi_print(GCRYMPI_FMT_HEX, elgamal_a_str, 512 / 8 * 1024, NULL, elgamal_a);
    if(err){
        printf("failed to convert the ciphertext value a.\n");
        exit(1);
    }
    
    FILE *fp_a = fopen("./ct_a", "wb");
    if(fp_a == NULL){
        printf("failed to store the ciphertext.\n");
        exit(1);
    }
    fprintf(fp_a, "%s\n", elgamal_a_str);
    fclose(fp_a);
    
    err = gcry_mpi_print(GCRYMPI_FMT_HEX, elgamal_b_str, 512 / 8 * 1024, NULL, elgamal_b);
    if(err){
        printf("failed to convert the ciphertext value b.\n");
        exit(1);
    }
    
    FILE *fp_b = fopen("./ct_b", "wb");
    if(fp_b == NULL){
        printf("failed to store the ciphertext.\n");
        exit(1);
    }
    fprintf(fp_b, "%s\n", elgamal_b_str);
    fclose(fp_b);
    gcry_mpi_release(plaintext);
    gcry_sexp_release(plaintext_exp);
    gcry_sexp_release(ciphertext_exp);
    gcry_sexp_release(elgamal_a_exp);
    gcry_sexp_release(elgamal_b_exp);
    gcry_mpi_release(elgamal_a);
    gcry_mpi_release(elgamal_b);
    free(elgamal_a_str);
    free(elgamal_b_str);
}

int main(){
    gcry_error_t err = 0;
    initialize();
    
    gcry_sexp_t elgamal_keypair;
    
    loadkey(&elgamal_keypair);
    encrypt(&elgamal_keypair);

    gcry_sexp_release(elgamal_keypair);

    return 0;
}
