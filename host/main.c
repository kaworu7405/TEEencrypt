/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[MAX_PLAIN_LEN_1024] = {0, };
	char encryptedKey[10] = {0, };
	char ciphertext[RSA_CIPHER_LEN_1024] = {0, };

	if(argv[1]==NULL){
		printf("please check your input!\n");
		return 0;
	}

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
					 TEEC_MEMREF_TEMP_INOUT, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = MAX_PLAIN_LEN_1024;
	op.params[2].tmpref.buffer = ciphertext;
	op.params[2].tmpref.size = RSA_CIPHER_LEN_1024;

	FILE* fp;

	if(argv[3]!=NULL) {
		if(!strcmp(argv[1], "-e") && !strcmp(argv[3], "Ceaser")) { 
			// read file
			fp = fopen(argv[2], "r");

			if(fp==NULL)
			{
				printf("can't find file '%s'\n", argv[2]);
			}
			else{
				fread(plaintext, 1, MAX_PLAIN_LEN_1024, fp);
				fclose(fp);
				memcpy(op.params[0].tmpref.buffer, plaintext, MAX_PLAIN_LEN_1024);

				// call TA
				res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_PLAIN_BY_C, &op,
						 &err_origin);
				if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);

				memcpy(ciphertext, op.params[2].tmpref.buffer, RSA_CIPHER_LEN_1024);

				//write file of chipertext
				fp = fopen("ciphertext_c.txt", "w");
				fputs(ciphertext, fp);
				fclose(fp);
				//convert int to char*
				sprintf(encryptedKey, "%d", op.params[1].value.a);

				//write file of encryptedKey
				fp = fopen("encryptedkey.txt", "w");
				fputs(encryptedKey, fp);
				fclose(fp);
				printf("Successfully encrypted by Ceaser\n");
			}
		} else if(!strcmp(argv[1], "-e")&&!strcmp(argv[3], "RSA")){
			// read file
			fp = fopen(argv[2], "r");

			if(fp==NULL)
			{
				printf("can't find file '%s'\n", argv[2]);
				return 0;
			}
			else{
				fread(plaintext, 1, MAX_PLAIN_LEN_1024, fp);
				fclose(fp);
				memcpy(op.params[0].tmpref.buffer, plaintext, MAX_PLAIN_LEN_1024);

				// call TA
				res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_GENKEYS, NULL, NULL);

				if (res != TEEC_SUCCESS)
					errx(1, "TA_TEEencrypt_CMD_GENKEYS failed with code 0x%x origin 0x%x", res, err_origin);

				res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_PLAIN_BY_R, &op, &err_origin);
				if (res != TEEC_SUCCESS)
					errx(1, "TA_TEEencrypt_CMD_ENC_PLAIN_BY_R with code 0x%x origin 0x%x", res, err_origin);

				memcpy(ciphertext, op.params[2].tmpref.buffer, RSA_CIPHER_LEN_1024);
				//write file of chipertext
				fp = fopen("ciphertext_r.txt", "w");
				fputs(ciphertext, fp);
				fclose(fp);
				printf("Successfully encrypted by RSA\n");
			}
		} else if(!strcmp(argv[1], "-d")) {
			fp = fopen(argv[2], "r");
			if(fp==NULL)
			{
				printf("can't find file '%s'\n", argv[2]);
			}
			else{
				fread(ciphertext, 1, RSA_CIPHER_LEN_1024, fp);
				fclose(fp);
				
				memcpy(op.params[2].tmpref.buffer, ciphertext, RSA_CIPHER_LEN_1024);
				
				fp = fopen(argv[3], "r");
				if(fp==NULL)
				{
					printf("can't find file '%s'\n", argv[2]);
				}
				fread(encryptedKey, 1, RSA_CIPHER_LEN_1024, fp);
				fclose(fp);
				//char* to int
				int _encryptedKey = atoi(encryptedKey);
				op.params[1].value.a = _encryptedKey;

				res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_CIPHER, &op,
						 &err_origin);

				if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);

				memcpy(plaintext, op.params[0].tmpref.buffer, MAX_PLAIN_LEN_1024);
				//write file of plaintext
				fp = fopen("plaintext.txt", "w");
				fputs(plaintext, fp);
				fclose(fp);
				printf("Successfully decrypted\n");
			}
		}
		else {
			printf("please check your input!\n");
		}
	} else {
		printf("please check your input!\n");
	}
	
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
