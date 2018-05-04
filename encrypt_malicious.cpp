#include <emp-tool/emp-tool.h>
#include <gcrypt.h>

// function taken from the Metal project
void aesgcm_encrypt(emp::PRG prg, unsigned char *input, unsigned char *output, const int input_len, int *output_len, uint8_t *key){
	uint8_t iv[16];
	prg.random_block((emp::block*)iv);

	gcry_cipher_hd_t handle;
	gcry_cipher_open(&handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
	gcry_cipher_setkey(handle, key, 16);
	gcry_cipher_setctr(handle, iv, 16);

	int blocks = input_len / 16;
	if(input_len % 16 != 0) blocks ++;

	memcpy(output, iv, 16);

	gcry_cipher_encrypt(handle, &output[16], 16 * blocks, input, 16 * blocks);

	uint8_t tag[16];
	gcry_cipher_gettag(handle, tag, 16);
	memcpy(&output[16 + 16 * blocks], tag, 16);

	*output_len = 16 /*IV*/ + 16 * blocks /*data*/ + 16 /*tag*/; 

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

int main(int argc, char **argv){
	if(argc != 3){
		printf("format: encrypt <filename_in> <filename_out>\n");
		return 0;
	}

	FILE *fp;
	int filesize_in;
	fp = fopen(argv[1], "rb");
	if(fp == NULL){
		printf("cannot open the input file.\n");
		return 0;
	}
	fseek(fp, 0, SEEK_END);
	filesize_in = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	unsigned char *message = (unsigned char*) calloc(16 + filesize_in, 1);
	unsigned char *message_encrypted = (unsigned char*) calloc(16 + 16 + 16 + filesize_in, 1);

	fread(message, filesize_in, 1, fp);
	fclose(fp);

	emp::block s;
	emp::block k;
	
	emp::PRG prg;
	prg.random_block(&s);

	emp::PRG prg_s(&s);
	prg_s.random_block(&k);

	bn_t q;
	eb_t g;
	const eb_t *gTbl;
	
	emp::initialize_relic();
	eb_curve_get_gen(g);
	eb_curve_get_ord(q);
	gTbl = eb_curve_get_tab();

	bn_t r_1;
	bn_t r_2;
	bn_t r_3;
	emp::bn_newl(r_1, r_2, r_3);
	prg.random_bn(r_1);
	prg_s.random_bn(r_2);
	prg.random_bn(r_3);

	eb_t pk_1;
	eb_t pk_2;
	eb_t pk_3;
	emp::eb_newl(pk_1, pk_2, pk_3);
	load_public_key(pk_1, 1);
	load_public_key(pk_2, 2);
	load_public_key(pk_3, 3);

	int output_len;
	aesgcm_encrypt(prg, message, message_encrypted, filesize_in, &output_len, (uint8_t*)&k);

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
	emp::eb_mul_fix_norm(c_1_part_1, gTbl, r_1);
	emp::eb_mul_fix_norm(c_2_part_1, gTbl, r_2);
	emp::eb_mul_fix_norm(c_3_part_1, gTbl, r_3);

	emp::eb_mul_norm(c_1_part_2_num, pk_1, r_1);
	emp::eb_mul_norm(c_2_part_2_num, pk_2, r_2);
	emp::eb_mul_norm(c_3_part_2_num, pk_3, r_3);

 	c_1_part_2 = emp::KDF(c_1_part_2_num);
	c_2_part_2 = emp::KDF(c_2_part_2_num);
	c_3_part_2 = emp::KDF(c_3_part_2_num);
	
	c_1_part_2 = emp::xorBlocks(c_1_part_2, s);
	c_2_part_2 = emp::xorBlocks(c_2_part_2, k);
	c_3_part_2 = emp::xorBlocks(c_3_part_2, k);

	// output file format
	//   size for c_1_part_1, c_2_part_1, c_3_part_1, message_encrypted, message_original_size
	//   c_1_part_1, c_2_part_1, c_3_part_1 (stored in EB_SIZE!)
	//   c_1_part_2, c_2_part_2, c_3_part_2
	//   message_encrypted

	int c_1_part_1_size;
	int c_2_part_1_size;
	int c_3_part_1_size;

	c_1_part_1_size = eb_size_bin(c_1_part_1, ECC_PACK);
	c_2_part_1_size = eb_size_bin(c_2_part_1, ECC_PACK);
	c_3_part_1_size = eb_size_bin(c_3_part_1, ECC_PACK);

	uint8_t c_1_part_1_buffer[EB_SIZE];
	uint8_t c_2_part_1_buffer[EB_SIZE];
	uint8_t c_3_part_1_buffer[EB_SIZE];

	memset(c_1_part_1_buffer, 0, sizeof(uint8_t) * EB_SIZE);
	memset(c_2_part_1_buffer, 0, sizeof(uint8_t) * EB_SIZE);
	memset(c_3_part_1_buffer, 0, sizeof(uint8_t) * EB_SIZE);

	eb_write_bin(c_1_part_1_buffer, c_1_part_1_size, c_1_part_1, ECC_PACK);
	eb_write_bin(c_2_part_1_buffer, c_2_part_1_size, c_2_part_1, ECC_PACK);
	eb_write_bin(c_3_part_1_buffer, c_3_part_1_size, c_3_part_1, ECC_PACK);

	fp = fopen(argv[2], "wb");
	if(fp == NULL){
		printf("cannot open the output file.\n");
		exit(1);
	}

	fwrite(&c_1_part_1_size, sizeof(int), 1, fp);
	fwrite(&c_2_part_1_size, sizeof(int), 1, fp);
	fwrite(&c_3_part_1_size, sizeof(int), 1, fp);
	fwrite(&output_len, sizeof(int), 1, fp);
	fwrite(&filesize_in, sizeof(int), 1, fp);

	fwrite(c_1_part_1_buffer, sizeof(uint8_t), EB_SIZE, fp);
	fwrite(c_2_part_1_buffer, sizeof(uint8_t), EB_SIZE, fp);
	fwrite(c_3_part_1_buffer, sizeof(uint8_t), EB_SIZE, fp);

	fwrite(&c_1_part_2, sizeof(emp::block), 1, fp);
	fwrite(&c_2_part_2, sizeof(emp::block), 1, fp);
	fwrite(&c_3_part_2, sizeof(emp::block), 1, fp);

	fwrite(message_encrypted, sizeof(unsigned char), output_len, fp);

	fclose(fp);

	emp::bn_freel(r_1, r_2, r_3);
	emp::eb_freel(pk_1, pk_2, pk_3);
	free(message);
	free(message_encrypted);
	emp::eb_freel(c_1_part_1, c_1_part_2_num, c_2_part_1, c_2_part_2_num, c_3_part_1, c_3_part_2_num);

	return 0;
}
