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

void keygen(gcry_sexp_t *pp, gcry_sexp_t *kp){
    gcry_error_t err = 0;
    err = gcry_sexp_build(pp, NULL, "(genkey (elg (nbits 3:512)))");
    if(err){
        printf("cannot establish the ElGamal key generation.\n");
        exit(1);
    }
    
    err = gcry_pk_genkey(kp, *pp);
    if(err){
        printf("cannot generate the ElGamal key pair.\n");
        exit(1);
    }
}

void savekey(gcry_sexp_t *kp){
    FILE *fp = fopen("./key", "wb");
    if(fp == NULL){
        printf("cannot create the key file.\n");
        exit(1);
    }

    void *elgamal_buf = malloc(512 / 8 * 1024);
    if(elgamal_buf == NULL){
        printf("failed to allocate the space to store the key.\n");
        exit(1);
    }
    
    size_t elgamal_buf_len;
    elgamal_buf_len = gcry_sexp_sprint(*kp, GCRYSEXP_FMT_DEFAULT, elgamal_buf, 512 / 8 * 1024);
    
    fwrite(elgamal_buf, 1, elgamal_buf_len, fp);
    fclose(fp);
    free(elgamal_buf);
}

void savepp(gcry_sexp_t *kp){
    gcry_error_t err = 0;
    gcry_sexp_t elgamal_p_exp = gcry_sexp_find_token(*kp, "p", 1);
    gcry_sexp_t elgamal_y_exp = gcry_sexp_find_token(*kp, "y", 1);
    
    gcry_mpi_t elgamal_p = gcry_mpi_new(1024);
    gcry_sexp_extract_param(elgamal_p_exp, NULL, "p", &elgamal_p, NULL);
    
    gcry_mpi_t elgamal_y = gcry_mpi_new(1024);
    gcry_sexp_extract_param(elgamal_y_exp, NULL, "y", &elgamal_y, NULL);
    
    void *elgamal_p_str = malloc(512 / 8 * 1024);
    if(elgamal_p_str == NULL){
        printf("failed to allocate the space to store the prime p.\n");
        exit(1);
    }
    
    err = gcry_mpi_print(GCRYMPI_FMT_HEX, elgamal_p_str, 512 / 8 * 1024, NULL, elgamal_p);
    if(err){
        printf("failed to convert the prime p.\n");
        exit(1);
    }
    FILE *fp_p = fopen("./p", "wb");
    if(fp_p == NULL){
        printf("failed to store the prime p.\n");
        exit(1);
    }
    fprintf(fp_p, "%s\n", elgamal_p_str);
    fclose(fp_p);
    
    void *elgamal_y_str = malloc(512 / 8 * 1024);
    if(elgamal_y_str == NULL){
        printf("failed to allocate the space to store the public key y.\n");
        exit(1);
    }
    
    err = gcry_mpi_print(GCRYMPI_FMT_HEX, elgamal_y_str, 512 / 8 * 1024, NULL, elgamal_y);
    if(err){
        printf("failed to convert the public key y.\n");
        exit(1);
    }
    FILE *fp_y = fopen("./y", "wb");
    if(fp_y == NULL){
        printf("failed to store the public key y.\n");
        exit(1);
    }
    fprintf(fp_y, "%s\n", elgamal_y_str);
    fclose(fp_y);
    gcry_sexp_release(elgamal_p_exp);
    gcry_sexp_release(elgamal_y_exp);
    gcry_mpi_release(elgamal_p);
    gcry_mpi_release(elgamal_y);
    free(elgamal_p_str);
    free(elgamal_y_str);
}

int main(){
    gcry_error_t err = 0;
    initialize();
    
    gcry_sexp_t elgamal_parms;
    gcry_sexp_t elgamal_keypair;
    
    keygen(&elgamal_parms, &elgamal_keypair);
    savekey(&elgamal_keypair);
    savepp(&elgamal_keypair);
    
    gcry_sexp_release(elgamal_parms);
    gcry_sexp_release(elgamal_keypair);

    return 0;
}
