#include <emp-tool/emp-tool.h>

int main(int argc, char **argv){
	eb_t g;
	bn_t q;
	emp::PRG prg;

	const eb_t *gTbl;

	if(argc != 2){
		printf("format: keygen <partyID>\n");
		return 0;
	}

	emp::initialize_relic();
	eb_curve_get_gen(g);
	eb_curve_get_ord(q);
	gTbl = eb_curve_get_tab();

	// choose a random secret key, generate the public key
	bn_t sk;
	eb_t pk;

	emp::eb_newl(pk);
	emp::bn_newl(sk);

	prg.random_bn(sk);
	emp::eb_mul_fix_norm(pk, gTbl, sk);
	
	
	// save the private key and public key
	uint64_t bn_buffer[4];
	int bn_size;
	memset(bn_buffer, 0, sizeof(uint64_t) * 4);

	uint8_t eb_buffer[EB_SIZE];
	int eb_size;
	memset(eb_buffer, 0, sizeof(uint8_t) * EB_SIZE);

	bn_size = bn_size_raw(sk);
	bn_write_raw(bn_buffer, bn_size, sk);
	
	eb_size = eb_size_bin(pk, ECC_PACK);
	eb_write_bin(eb_buffer, eb_size, pk, ECC_PACK);

	FILE *fp;
	char filename[100];
	sprintf(filename, "./pk_%s", argv[1]);
	fp = fopen(filename, "wb");
	if(fp == NULL){
		printf("cannot open the file\n");
		return 0;
	}
	fwrite(&eb_size, sizeof(int), 1, fp);
	fwrite(eb_buffer, sizeof(uint8_t), EB_SIZE, fp);
	fclose(fp);

	sprintf(filename, "./sk_%s", argv[1]);
        fp = fopen(filename, "wb");
        if(fp == NULL){
                printf("cannot open the file\n");
                return 0;
        }
        fwrite(&bn_size, sizeof(int), 1, fp);
        fwrite(bn_buffer, sizeof(uint64_t), 4, fp);
        fclose(fp);

	emp::eb_freel(pk);
	emp::bn_freel(sk);

	return 0;
}
