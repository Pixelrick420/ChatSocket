gcc client.c ../Utils/socketUtil.c ../Utils/sha256.c ../Utils/aes.c -o client -lpthread -lssl -lcrypto
./client