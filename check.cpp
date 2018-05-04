#include <emp-tool/emp-tool.h>
#include <gcrypt.h>

// function taken from the Metal project
void aesgcm_decrypt(unsigned char *input, unsigned char *output, const int input_len, int *output_len, uint8_t *key, bool *valid){
	uint8_t iv[16];
	memcpy(iv, input, 16);

	gcry_cipher_hd_t handle;
	gcry_cipher_open(&handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
	gcry_cipher_setkey(handle, key, 16);
	gcry_cipher_setctr(handle, iv, 16);

	int blocks = (input_len - 32) / 16;

	gcry_cipher_decrypt(handle, output, 16 * blocks, &input[16], 16 * blocks);

	uint8_t tag[16];
	memcpy(tag, &input[16 + 16 * blocks], 16);

	gcry_error_t checktag_error = gcry_cipher_checktag(handle, tag, 16);
	if(gcry_err_code(checktag_error) == GPG_ERR_CHECKSUM){
		*valid = false;
	}else{
		*valid = true;
	}

	*output_len = 16 * blocks;
	gcry_cipher_close(handle);
}

void load_public_key(eb_t eb, int party){
	char filename[100];
	sprintf(filename, "pk_%d", party);

	FILE *fp;
	fp = fopen(filename, "rb");
	int eb_size;
	if(fp == NULL){
		printf("cannot open the public key file.\n");
		exit(1);
	}
	fread(&eb_size, sizeof(int), 1, fp);

	uint8_t eb_buffer[EB_SIZE];
	memset(eb_buffer, 0, EB_SIZE * sizeof(uint8_t));
	fread(eb_buffer, eb_size, sizeof(uint8_t), fp);
	
	eb_read_bin(eb, eb_buffer, eb_size);
}

void load_private_key(bn_t bn, int party){
	char filename[100];
	sprintf(filename, "sk_%d", party);

	FILE *fp;
	fp = fopen(filename, "rb");
	int bn_size;
	if(fp == NULL){
		printf("cannot open the private key file.\n");
		exit(1);
	}
	fread(&bn_size, sizeof(int), 1, fp);

	uint64_t bn_buffer[4];
	memset(bn_buffer, 0, 4 * sizeof(uint64_t));
	fread(bn_buffer, 4, sizeof(uint64_t), fp);
	
	bn_read_raw(bn, bn_buffer, bn_size);
}

int main(int argc, char **argv){
	if(argc != 2){
		printf("format: check <filename_in>\n");
		return 0;
	}

	emp::block s;
        emp::block k;
	
	bn_t sk;
	bn_t q;
	eb_t g;
	const eb_t *gTbl;
	
	emp::initialize_relic();
	emp::bn_newl(sk);
	eb_curve_get_gen(g);
	eb_curve_get_ord(q);
	gTbl = eb_curve_get_tab();

	int c_1_part_1_size;
        int c_2_part_1_size;
        int c_3_part_1_size;
	int message_encrypted_len;
	int message_original_len;

	FILE *fp;
	fp = fopen(argv[1], "rb");
	if(fp == NULL){
		printf("cannot open the input file.\n");
		return 0;
	}

	fread(&c_1_part_1_size, sizeof(int), 1, fp);
	fread(&c_2_part_1_size, sizeof(int), 1, fp);
	fread(&c_3_part_1_size, sizeof(int), 1, fp);
	fread(&message_encrypted_len, sizeof(int), 1, fp);
	fread(&message_original_len, sizeof(int), 1, fp);

	unsigned char *message_encrypted = (unsigned char*) calloc(message_encrypted_len, 1);
	unsigned char *message_decrypted = (unsigned char*) calloc(message_encrypted_len, 1);

	uint8_t c_1_part_1_buffer[EB_SIZE];
        uint8_t c_2_part_1_buffer[EB_SIZE];
        uint8_t c_3_part_1_buffer[EB_SIZE];

        memset(c_1_part_1_buffer, 0, sizeof(uint8_t) * EB_SIZE);
        memset(c_2_part_1_buffer, 0, sizeof(uint8_t) * EB_SIZE);
        memset(c_3_part_1_buffer, 0, sizeof(uint8_t) * EB_SIZE);

	fread(c_1_part_1_buffer, sizeof(uint8_t), EB_SIZE, fp);
	fread(c_2_part_1_buffer, sizeof(uint8_t), EB_SIZE, fp);
	fread(c_3_part_1_buffer, sizeof(uint8_t), EB_SIZE, fp);

	eb_t c_1_part_1;
        eb_t c_1_part_2_num;
        emp::block c_1_part_2;

        eb_t c_2_part_1;
        eb_t c_2_part_2_num;
        emp::block c_2_part_2;

        eb_t c_3_part_1;
        eb_t c_3_part_2_num;
        emp::block c_3_part_2;

        emp::eb_newl(c_1_part_1, c_1_part_2_num, c_2_part_1, c_2_part_2_num, c_3_part_1, c_3_part_2_num);	

	eb_read_bin(c_1_part_1, c_1_part_1_buffer, c_1_part_1_size);
	eb_read_bin(c_2_part_1, c_2_part_1_buffer, c_2_part_1_size);
	eb_read_bin(c_3_part_1, c_3_part_1_buffer, c_3_part_1_size);

	fread(&c_1_part_2, sizeof(emp::block), 1, fp);
	fread(&c_2_part_2, sizeof(emp::block), 1, fp);
	fread(&c_3_part_2, sizeof(emp::block), 1, fp);

	fread(message_encrypted, message_encrypted_len, 1, fp);
	fclose(fp);

	load_private_key(sk, 1);
	emp::eb_mul_norm(c_1_part_2_num, c_1_part_1, sk);

	emp::block tmp;
	tmp = emp::KDF(c_1_part_2_num);

	s = emp::xorBlocks(tmp, c_1_part_2);
		
	emp::PRG prg_s(&s);
	prg_s.random_block(&k);

	bn_t r_2;
	bn_t r_3;
	emp::bn_newl(r_2, r_3);
	prg_s.random_bn(r_2);
	prg_s.random_bn(r_3);

	eb_t pk_1;
	eb_t pk_2;
	eb_t pk_3;
	emp::eb_newl(pk_1, pk_2, pk_3);
	load_public_key(pk_1, 1);
	load_public_key(pk_2, 2);
	load_public_key(pk_3, 3);

	// party 2 party 3's part 1 check
	eb_t c_2_part_1_correct;
	eb_t c_3_part_1_correct;
	emp::eb_newl(c_2_part_1_correct, c_3_part_1_correct);

	emp::eb_mul_fix_norm(c_2_part_1_correct, gTbl, r_2);
	emp::eb_mul_fix_norm(c_3_part_1_correct, gTbl, r_3);

	if(eb_cmp(c_2_part_1_correct, c_2_part_1) != CMP_EQ){
		printf("the party 2's first part is not from a honest encryption.\n");
		exit(0);
	}

	if(eb_cmp(c_3_part_1_correct, c_3_part_1) != CMP_EQ){
                printf("the party 3's first part is not from a honest encryption.\n");
                exit(0);
        }

	// party 2 party 3's part 2 check
	emp::eb_mul_norm(c_2_part_2_num, pk_2, r_2);
	emp::eb_mul_norm(c_3_part_2_num, pk_3, r_3);

	emp::block c_2_part_2_correct;
	emp::block c_3_part_2_correct;

	c_2_part_2_correct = emp::KDF(c_2_part_2_num);
	c_3_part_2_correct = emp::KDF(c_3_part_2_num);

	c_2_part_2_correct = emp::xorBlocks(c_2_part_2_correct, k);
	c_3_part_2_correct = emp::xorBlocks(c_3_part_2_correct, k);

	if(emp::cmpBlock(&c_2_part_2_correct, &c_2_part_2, 1) == false){
		printf("the party 2's second part is not from a honest encryption.\n");
                exit(0);
	}

	if(emp::cmpBlock(&c_3_part_2_correct, &c_3_part_2, 1) == false){
                printf("the party 2's second part is not from a honest encryption.\n");
                exit(0);
        }


	bool valid;
	int output_len;
	aesgcm_decrypt(message_encrypted, message_decrypted, message_encrypted_len, &output_len, (uint8_t *)&k, &valid);

	if(valid == false){
		printf("decrypted result is invalid.\n");
		exit(0);
	}

	printf("pass.\n");

	emp::bn_freel(sk);
	free(message_decrypted);
	free(message_encrypted);
	
	emp::eb_freel(pk_1, pk_2, pk_3);
	emp::bn_freel(r_2, r_3);
	emp::eb_freel(c_2_part_1_correct, c_3_part_1_correct);
	emp::eb_freel(c_1_part_1, c_1_part_2_num, c_2_part_1, c_2_part_2_num, c_3_part_1, c_3_part_2_num);

	return 0;
}
