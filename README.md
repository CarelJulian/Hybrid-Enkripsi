# Hybrid Enkripsi
Aplikasi ini adalah implementasi Hybrid Encryption, yaitu metode pengamanan data yang menggabungkan enkripsi AES & RSA. Dengan metode hybrid karena AES cepat untuk file besar, sedangkan RSA aman untuk pertukaran kunci. Aplikasi ini dibuat sebagai bentuk penerapan teknologi enkripsi
## Care penggunaan :
- install dependencies dengan mengetik pada powershell : pip install cryptography
- Generate RSA KEY yang membuat 2 file : python hybrid_crypto.py genkeys --private private.pem --public public.pem
- Menyiapkan file yang akan dienkripsi (data.txt yang berisi tulisan rahasia)
- Enkripsi file : python hybrid_crypto.py encrypt --in data.txt --out file_encrypted.bin --keyout key_encrypted.bin --pub public.pem
- Dekripsi file : python hybrid_crypto.py decrypt --in file_encrypted.bin --keyin key_encrypted.bin --priv private.pem --out file_decrypted.txt
## Hasil file terenkripsi :
<img width="989" height="500" alt="Image" src="https://github.com/user-attachments/assets/075bd926-707a-4c92-97fb-7540c55d3ed9" />

## Hasik file dekripsi : 
<img width="985" height="503" alt="Image" src="https://github.com/user-attachments/assets/2902eeb8-f21a-4996-bdc9-a788044e6b03" />

## Contoh hasil pada powershell :
<img width="1715" height="203" alt="Image" src="https://github.com/user-attachments/assets/c355df6d-84f1-45f7-b265-8e30118d2a12" />
