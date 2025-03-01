# RSA-Based-Encrypted-Key-Exchange-EKE-

# Pendahuluan
Protokol RSA-Based EKE (Encrypted Key Exchange) adalah salah satu metode yang digunakan untuk menjamin keamanan komunikasi antara dua pihak yang ingin bertukar informasi secara aman. Dalam protokol ini, enkripsi kunci publik RSA digunakan untuk otentikasi dan pertukaran kunci sesi yang aman antara klien dan server. Protokol ini dapat digunakan untuk memastikan bahwa pesan yang dikirimkan tidak dapat dibaca oleh pihak ketiga, dan hanya pihak yang berwenang yang dapat mengakses informasi yang dikirimkan.

# Protokol
Protokol RSA-Based EKE terdiri dari tiga langkah yang dijelaskan sebagai berikut:
1.	Langkah 1: Inisialisasi
-	Server menghasilkan pasangan kunci RSA (Kpub, Kpriv) dan menyimpan kata sandi pengguna dalam format hash yang aman.
2.	Langkah 2: Otentikasi
-	Klien mengenkripsi kata sandinya menggunakan kunci publik RSA milik server: EKpub(Password).
-	Klien mengirimkan pesan yang berisi hasil enkripsi kata sandi ke server.
-	Server mendekripsi pesan menggunakan kunci privat RSA dan memverifikasi kata sandi yang terkandung di dalamnya.
3.	Langkah 3: Pertukaran Kunci Sesi
-	Server menghasilkan kunci sesi (Ks) dan mengenkripsinya dengan kunci publik RSA milik klien.
-	Server mengirimkan pesan yang berisi kunci sesi yang terenkripsi ke klien.
-	Klien mendekripsi pesan tersebut dan mendapatkan kunci sesi yang digunakan untuk komunikasi aman.

# Mitigasi Replay Attack
RSA Serangan replay terjadi ketika penyerang mengirim ulang pesan yang sah untuk menipu sistem. Untuk mencegahnya, protokol EKE dapat dilengkapi dengan nonce (number used once) yang unik untuk setiap sesi.

Metode Mitigasi
	Setiap pesan antara klien dan server menyertakan nonce unik.
	Server menyimpan daftar nonce yang telah digunakan untuk mendeteksi duplikasi.
	Jika nonce sudah pernah digunakan, server menolak permintaan.

Langkah Implementasi
	Klien mengenkripsi kata sandi bersama nonce acak:
M1=EKpub(Password,Nonce).\ 
	Server mendekripsi M1 dan memverifikasi bahwa nonce belum pernah digunakan. 
	Server membalas dengan kunci sesi dan nonce baru:
M2=EKpub(Ks,Nonce\prime).\ 
	Klien memverifikasi bahwa Nonce′ sesuai dengan yang dikirim oleh server.

