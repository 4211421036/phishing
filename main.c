#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <dirent.h>

#define MAX_URL_LENGTH 1024
#define MAX_BUFFER_SIZE 8192
#define MAX_PATH_LENGTH 512
#define SAMPLE_SIZE 256

// Thresholds berdasarkan jurnal
#define ENTROPY_THRESHOLD_HIGH 7.0
#define ENTROPY_THRESHOLD_LOW 6.0
#define SUSPICIOUS_EXTENSIONS_COUNT 5

// Ekstensi yang mencurigakan
const char* suspicious_extensions[] = {
    ".exe", ".apk", ".bat", ".cmd", ".msi", ".js", ".vbs", ".scr"
};

// Fungsi untuk menghitung entropi Shannon
double calculate_shannon_entropy(unsigned char* data, size_t size) {
    if (size == 0) return 0.0;
    
    double entropy = 0.0;
    int count[256] = {0};
    
    // Hitung frekuensi kemunculan setiap byte
    for (size_t i = 0; i < size; i++) {
        count[data[i]]++;
    }
    
    // Hitung entropi Shannon
    for (int i = 0; i < 256; i++) {
        if (count[i] > 0) {
            double probability = (double)count[i] / size;
            entropy -= probability * log2(probability);
        }
    }
    
    return entropy;
}

// Fungsi untuk menghitung entropi Renyi
double calculate_renyi_entropy(unsigned char* data, size_t size, double alpha) {
    if (size == 0) return 0.0;
    if (alpha == 1.0) return calculate_shannon_entropy(data, size);
    
    int count[256] = {0};
    double sum = 0.0;
    
    // Hitung frekuensi kemunculan setiap byte
    for (size_t i = 0; i < size; i++) {
        count[data[i]]++;
    }
    
    // Hitung entropi Renyi
    for (int i = 0; i < 256; i++) {
        if (count[i] > 0) {
            double probability = (double)count[i] / size;
            sum += pow(probability, alpha);
        }
    }
    
    return (1.0 / (1.0 - alpha)) * log2(sum);
}

// Fungsi untuk menghitung entropi Tsallis
double calculate_tsallis_entropy(unsigned char* data, size_t size, double q) {
    if (size == 0) return 0.0;
    if (q == 1.0) return calculate_shannon_entropy(data, size);
    
    int count[256] = {0};
    double sum = 0.0;
    
    // Hitung frekuensi kemunculan setiap byte
    for (size_t i = 0; i < size; i++) {
        count[data[i]]++;
    }
    
    // Hitung entropi Tsallis
    for (int i = 0; i < 256; i++) {
        if (count[i] > 0) {
            double probability = (double)count[i] / size;
            sum += pow(probability, q);
        }
    }
    
    return (1.0 / (q - 1.0)) * (1.0 - sum);
}

// Fungsi untuk memeriksa apakah URL mencurigakan
int is_suspicious_url(const char* url) {
    // Kriteria dasar untuk URL phishing
    if (strstr(url, "login") && strstr(url, "redirect")) return 1;
    if (strstr(url, "security") && strstr(url, "verify")) return 1;
    if (strstr(url, "account") && strstr(url, "update")) return 1;
    if (strstr(url, "confirm") && strstr(url, "payment")) return 1;
    if (strstr(url, "password") && strstr(url, "reset")) return 1;
    
    // Cek domain yang mencurigakan
    if (strstr(url, "paypa1.com") || strstr(url, "amaz0n.com") || 
        strstr(url, "goog1e.com") || strstr(url, "m1crosoft.com")) {
        return 1;
    }
    
    // Cek parameter yang mencurigakan
    if (strstr(url, "?cmd=") || strstr(url, "?exe=") || 
        strstr(url, "?admin=") || strstr(url, "?root=")) {
        return 1;
    }
    
    // Cek penggunaan IP daripada domain
    int dots = 0, digits = 1;
    for (int i = 0; url[i] != '\0' && url[i] != '/'; i++) {
        if (url[i] == '.') {
            dots++;
            digits = 1;
        } else if (!isdigit(url[i])) {
            digits = 0;
        }
    }
    if (dots == 3 && digits) return 1;
    
    return 0;
}

// Fungsi untuk memeriksa ekstensi file yang mencurigakan
int has_suspicious_extension(const char* filename) {
    const char* extension = strrchr(filename, '.');
    if (extension) {
        for (int i = 0; i < SUSPICIOUS_EXTENSIONS_COUNT; i++) {
            if (strcmp(extension, suspicious_extensions[i]) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

// Fungsi untuk memeriksa apakah file mencurigakan berdasarkan entropi
int is_suspicious_file(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Tidak dapat membuka file %s\n", filename);
        return -1;
    }
    
    // Baca header file (256 byte pertama)
    unsigned char header[SAMPLE_SIZE];
    size_t header_size = fread(header, 1, SAMPLE_SIZE, file);
    
    // Baca seluruh file
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    unsigned char* full_content = (unsigned char*)malloc(file_size);
    if (!full_content) {
        printf("Error: Tidak dapat mengalokasikan memori\n");
        fclose(file);
        return -1;
    }
    
    size_t read_size = fread(full_content, 1, file_size, file);
    fclose(file);
    
    // Hitung entropi Shannon dan Renyi
    double shannon_entropy_header = calculate_shannon_entropy(header, header_size);
    double renyi_entropy_header = calculate_renyi_entropy(header, header_size, 2.0);
    double avg_entropy_header = (shannon_entropy_header + renyi_entropy_header) / 2.0;
    
    double shannon_entropy_full = calculate_shannon_entropy(full_content, read_size);
    double renyi_entropy_full = calculate_renyi_entropy(full_content, read_size, 2.0);
    double avg_entropy_full = (shannon_entropy_full + renyi_entropy_full) / 2.0;
    
    free(full_content);
    
    // Berdasarkan penelitian, entropi tinggi pada header dan konten penuh menunjukkan file terenkripsi
    // yang mungkin berbahaya seperti file ransomware
    double header_diff = 7.0 - avg_entropy_header;
    double full_diff = 8.0 - avg_entropy_full;
    double total_diff = header_diff + full_diff;
    
    // Menerapkan metode deteksi dari jurnal
    // Jika total_diff < 0.5, kemungkinan besar file terenkripsi (WannaCry pattern)
    if (total_diff < 0.5) {
        return 1;
    }
    
    // Jika entropi header tinggi dan entropi file tinggi, kemungkinan besar file terenkripsi
    if (avg_entropy_header > ENTROPY_THRESHOLD_HIGH && avg_entropy_full > ENTROPY_THRESHOLD_HIGH) {
        return 1;
    }
    
    // Periksa ekstensi file
    if (has_suspicious_extension(filename)) {
        return 1;
    }
    
    return 0;
}

// Fungsi untuk memeriksa apakah dokumen PDF mencurigakan
int is_suspicious_pdf(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Tidak dapat membuka file %s\n", filename);
        return -1;
    }
    
    // Baca header PDF untuk memastikan ini benar-benar PDF
    char header[8];
    if (fread(header, 1, 8, file) != 8 || strncmp(header, "%PDF-1.", 7) != 0) {
        fclose(file);
        return 1; // Bukan PDF valid
    }
    
    // Cari string JavaScript atau /JS dalam file
    unsigned char buffer[MAX_BUFFER_SIZE];
    size_t bytes_read;
    int found_js = 0;
    int found_launch = 0;
    int found_embedfile = 0;
    
    while ((bytes_read = fread(buffer, 1, MAX_BUFFER_SIZE, file)) > 0) {
        // Ubah buffer menjadi string C dengan null terminator
        char temp_buffer[MAX_BUFFER_SIZE + 1];
        memcpy(temp_buffer, buffer, bytes_read);
        temp_buffer[bytes_read] = '\0';
        
        // Cari string mencurigakan
        if (strstr(temp_buffer, "/JavaScript") || strstr(temp_buffer, "/JS")) {
            found_js = 1;
        }
        if (strstr(temp_buffer, "/Launch")) {
            found_launch = 1;
        }
        if (strstr(temp_buffer, "/EmbeddedFile") || strstr(temp_buffer, "/Filespec")) {
            found_embedfile = 1;
        }
    }
    
    fclose(file);
    
    // Jika ditemukan JavaScript dan Launch atau EmbeddedFile, kemungkinan PDF berbahaya
    if (found_js && (found_launch || found_embedfile)) {
        return 1;
    }
    
    return 0;
}

// Fungsi utama untuk memeriksa file
int check_file(const char* filename) {
    // Periksa ekstensi file
    const char* extension = strrchr(filename, '.');
    if (!extension) {
        printf("Error: File tidak memiliki ekstensi\n");
        return -1;
    }
    
    // Periksa apakah file PDF
    if (strcmp(extension, ".pdf") == 0) {
        return is_suspicious_pdf(filename);
    }
    
    // Periksa file lainnya
    return is_suspicious_file(filename);
}

// Fungsi untuk memeriksa direktori
void scan_directory(const char* directory) {
    DIR* dir;
    struct dirent* entry;
    char path[MAX_PATH_LENGTH];
    
    if (!(dir = opendir(directory))) {
        printf("Error: Tidak dapat membuka direktori %s\n", directory);
        return;
    }
    
    printf("Scanning direktori %s...\n", directory);
    
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        
        // Periksa file
        int result = check_file(path);
        if (result == 1) {
            printf("PERINGATAN: File %s mencurigakan (kemungkinan phishing atau malware)!\n", path);
        } else if (result == 0) {
            printf("File %s aman.\n", path);
        }
    }
    
    closedir(dir);
    printf("Scanning selesai.\n");
}

int main() {
    int choice;
    char url[MAX_URL_LENGTH];
    char filepath[MAX_PATH_LENGTH];
    char directory[MAX_PATH_LENGTH];
    
    printf("========= Aplikasi Deteksi Phishing & Malware =========\n");
    printf("Aplikasi ini menggunakan metode entropy-based untuk deteksi file berbahaya\n");
    printf("Referensi: Entropy Based Method for Malicious File Detection\n\n");
    
    while (1) {
        printf("\nPilih opsi:\n");
        printf("1. Periksa URL\n");
        printf("2. Periksa File\n");
        printf("3. Scan Direktori\n");
        printf("4. Keluar\n");
        printf("Pilihan Anda: ");
        scanf("%d", &choice);
        getchar(); // Membersihkan buffer
        
        switch (choice) {
            case 1:
                printf("Masukkan URL untuk diperiksa: ");
                fgets(url, MAX_URL_LENGTH, stdin);
                url[strcspn(url, "\n")] = 0; // Hapus newline
                
                if (is_suspicious_url(url)) {
                    printf("URL tersebut mencurigakan! Kemungkinan besar phishing.\n");
                } else {
                    printf("URL tersebut tampaknya aman.\n");
                }
                break;
                
            case 2:
                printf("Masukkan path file untuk diperiksa: ");
                fgets(filepath, MAX_PATH_LENGTH, stdin);
                filepath[strcspn(filepath, "\n")] = 0; // Hapus newline
                
                int result = check_file(filepath);
                if (result == 1) {
                    printf("PERINGATAN: File mencurigakan! Kemungkinan phishing atau malware.\n");
                } else if (result == 0) {
                    printf("File tampaknya aman.\n");
                }
                break;
                
            case 3:
                printf("Masukkan path direktori untuk di-scan: ");
                fgets(directory, MAX_PATH_LENGTH, stdin);
                directory[strcspn(directory, "\n")] = 0; // Hapus newline
                
                scan_directory(directory);
                break;
                
            case 4:
                printf("Terima kasih telah menggunakan aplikasi ini.\n");
                return 0;
                
            default:
                printf("Pilihan tidak valid. Coba lagi.\n");
        }
    }
    
    return 0;
}
