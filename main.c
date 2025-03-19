// PhishingMalwareDetector.c
// Aplikasi GUI untuk deteksi phishing & malware berbasis GTK

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <dirent.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <pthread.h>

#define MAX_URL_LENGTH 1024
#define MAX_BUFFER_SIZE 8192
#define MAX_PATH_LENGTH 512
#define SAMPLE_SIZE 256
#define APP_VERSION "1.0.0"
#define GITHUB_API_URL "https://api.github.com/repos/4211421036/phishing/releases/latest"

// Thresholds berdasarkan jurnal
#define ENTROPY_THRESHOLD_HIGH 7.0
#define ENTROPY_THRESHOLD_LOW 6.0
#define SUSPICIOUS_EXTENSIONS_COUNT 8

// Ekstensi yang mencurigakan
const char* suspicious_extensions[] = {
    ".exe", ".apk", ".bat", ".cmd", ".msi", ".js", ".vbs", ".scr"
};

typedef struct {
    GtkWidget *window;
    GtkWidget *notebook;
    GtkWidget *url_entry;
    GtkWidget *url_result_label;
    GtkWidget *file_chooser_button;
    GtkWidget *file_result_label;
    GtkWidget *dir_chooser_button;
    GtkWidget *dir_result_textview;
    GtkWidget *scan_progress;
    GtkWidget *status_bar;
    GtkTextBuffer *dir_result_buffer;
} AppWidgets;

typedef struct {
    char *data;
    size_t size;
} UpdateData;

typedef struct {
    const char *directory;
    AppWidgets *widgets;
    GtkTextBuffer *buffer;
} ScanDirThreadData;

// Prototype fungsi
double calculate_shannon_entropy(unsigned char* data, size_t size);
double calculate_renyi_entropy(unsigned char* data, size_t size, double alpha);
double calculate_tsallis_entropy(unsigned char* data, size_t size, double q);
int is_suspicious_url(const char* url);
int has_suspicious_extension(const char* filename);
int is_suspicious_file(const char* filename);
int is_suspicious_pdf(const char* filename);
int check_file(const char* filename);
void* scan_directory_thread(void *arg);
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
void check_for_updates();
gboolean update_progress_bar(gpointer data);

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
        return -1;
    }
    
    // Periksa apakah file PDF
    if (strcmp(extension, ".pdf") == 0) {
        return is_suspicious_pdf(filename);
    }
    
    // Periksa file lainnya
    return is_suspicious_file(filename);
}

// Fungsi callback untuk update progress bar
gboolean update_progress_bar(gpointer data) {
    GtkWidget *progress_bar = (GtkWidget *)data;
    static gdouble fraction = 0.0;
    
    // Update progress bar
    fraction += 0.01;
    if (fraction > 1.0) fraction = 0.0;
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progress_bar), fraction);
    
    return TRUE;  // Continue calling
}

// Fungsi thread untuk scan direktori
void* scan_directory_thread(void *arg) {
    ScanDirThreadData *thread_data = (ScanDirThreadData *)arg;
    const char* directory = thread_data->directory;
    GtkTextBuffer *buffer = thread_data->buffer;
    AppWidgets *widgets = thread_data->widgets;
    
    DIR* dir;
    struct dirent* entry;
    char path[MAX_PATH_LENGTH];
    char message[MAX_BUFFER_SIZE];
    GtkTextIter iter;
    
    // Set status
    gdk_threads_enter();
    gtk_text_buffer_get_end_iter(buffer, &iter);
    gtk_text_buffer_insert(buffer, &iter, "Scanning direktori...\n", -1);
    gdk_threads_leave();
    
    if (!(dir = opendir(directory))) {
        gdk_threads_enter();
        gtk_text_buffer_get_end_iter(buffer, &iter);
        sprintf(message, "Error: Tidak dapat membuka direktori %s\n", directory);
        gtk_text_buffer_insert(buffer, &iter, message, -1);
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(widgets->scan_progress), 0.0);
        gdk_threads_leave();
        free(thread_data);
        return NULL;
    }
    
    // Mulai timer untuk progress bar
    guint timer_id = g_timeout_add(50, update_progress_bar, widgets->scan_progress);
    
    // Scan direktori
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        
        // Periksa file
        int result = check_file(path);
        
        // Update UI
        gdk_threads_enter();
        gtk_text_buffer_get_end_iter(buffer, &iter);
        
        if (result == 1) {
            sprintf(message, "⚠️ PERINGATAN: File %s mencurigakan (kemungkinan phishing/malware)!\n", path);
            gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, message, -1, "warning", NULL);
        } else if (result == 0) {
            sprintf(message, "✅ File %s aman.\n", path);
            gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, message, -1, "safe", NULL);
        } else {
            sprintf(message, "❓ File %s tidak dapat diperiksa.\n", path);
            gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, message, -1, "error", NULL);
        }
        
        // Scroll ke bawah
        GtkTextMark *mark = gtk_text_buffer_get_insert(buffer);
        gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(widgets->dir_result_textview), mark, 0.0, TRUE, 0.5, 0.5);
        
        gdk_threads_leave();
    }
    
    closedir(dir);
    
    // Stop timer dan update UI
    g_source_remove(timer_id);
    
    gdk_threads_enter();
    gtk_text_buffer_get_end_iter(buffer, &iter);
    gtk_text_buffer_insert(buffer, &iter, "\n✨ Scanning selesai!\n", -1);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(widgets->scan_progress), 1.0);
    gtk_statusbar_push(GTK_STATUSBAR(widgets->status_bar), 0, "Scanning selesai");
    gdk_threads_leave();
    
    free(thread_data);
    return NULL;
}

// Fungsi callback untuk URL check button
static void on_check_url_clicked(GtkButton *button, AppWidgets *widgets) {
    const gchar *url = gtk_entry_get_text(GTK_ENTRY(widgets->url_entry));
    
    if (strlen(url) == 0) {
        gtk_label_set_markup(GTK_LABEL(widgets->url_result_label), "Silahkan masukkan URL");
        return;
    }
    
    gtk_statusbar_push(GTK_STATUSBAR(widgets->status_bar), 0, "Memeriksa URL...");
    
    // Periksa URL
    if (is_suspicious_url(url)) {
        gtk_label_set_markup(GTK_LABEL(widgets->url_result_label), 
            "<span foreground='red' weight='bold'>⚠️ URL mencurigakan! Kemungkinan Phishing!</span>");
    } else {
        gtk_label_set_markup(GTK_LABEL(widgets->url_result_label), 
            "<span foreground='green' weight='bold'>✅ URL tampaknya aman</span>");
    }
    
    gtk_statusbar_push(GTK_STATUSBAR(widgets->status_bar), 0, "URL sudah diperiksa");
}

// Fungsi callback untuk File check button
static void on_check_file_clicked(GtkButton *button, AppWidgets *widgets) {
    gchar *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(widgets->file_chooser_button));
    
    if (!filename) {
        gtk_label_set_markup(GTK_LABEL(widgets->file_result_label), "Silahkan pilih file");
        return;
    }
    
    gtk_statusbar_push(GTK_STATUSBAR(widgets->status_bar), 0, "Memeriksa file...");
    
    // Reset progress bar dan start animation
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(widgets->scan_progress), 0.0);
    guint timer_id = g_timeout_add(50, update_progress_bar, widgets->scan_progress);
    
    // Periksa file
    int result = check_file(filename);
    
    // Stop animation
    g_source_remove(timer_id);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(widgets->scan_progress), 1.0);
    
    if (result == 1) {
        gtk_label_set_markup(GTK_LABEL(widgets->file_result_label), 
            "<span foreground='red' weight='bold'>⚠️ File mencurigakan! Kemungkinan phishing atau malware!</span>");
    } else if (result == 0) {
        gtk_label_set_markup(GTK_LABEL(widgets->file_result_label), 
            "<span foreground='green' weight='bold'>✅ File tampaknya aman</span>");
    } else {
        gtk_label_set_markup(GTK_LABEL(widgets->file_result_label), 
            "<span foreground='orange' weight='bold'>❓ File tidak dapat diperiksa</span>");
    }
    
    g_free(filename);
    gtk_statusbar_push(GTK_STATUSBAR(widgets->status_bar), 0, "File sudah diperiksa");
}

// Fungsi callback untuk Directory scan button
static void on_scan_directory_clicked(GtkButton *button, AppWidgets *widgets) {
    gchar *dirname = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(widgets->dir_chooser_button));
    
    if (!dirname) {
        GtkTextIter iter;
        gtk_text_buffer_get_end_iter(widgets->dir_result_buffer, &iter);
        gtk_text_buffer_insert(widgets->dir_result_buffer, &iter, "Silahkan pilih direktori\n", -1);
        return;
    }
    
    // Clear previous results
    gtk_text_buffer_set_text(widgets->dir_result_buffer, "", -1);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(widgets->scan_progress), 0.0);
    
    gtk_statusbar_push(GTK_STATUSBAR(widgets->status_bar), 0, "Scanning direktori...");
    
    // Create thread data
    ScanDirThreadData *thread_data = malloc(sizeof(ScanDirThreadData));
    thread_data->directory = dirname;
    thread_data->buffer = widgets->dir_result_buffer;
    thread_data->widgets = widgets;
    
    // Create and start scan thread
    pthread_t scan_thread;
    pthread_create(&scan_thread, NULL, scan_directory_thread, thread_data);
    pthread_detach(scan_thread);
}

// Callback untuk curl
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    UpdateData *mem = (UpdateData *)userp;
    
    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if(!ptr) {
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }
    
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    
    return realsize;
}

// Fungsi untuk memeriksa update
void check_for_updates() {
    CURL *curl;
    CURLcode res;
    UpdateData update_data;
    
    update_data.data = malloc(1);
    update_data.size = 0;
    
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    
    if(curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "User-Agent: PhishingDetector/1.0");
        
        curl_easy_setopt(curl, CURLOPT_URL, GITHUB_API_URL);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&update_data);
        
        res = curl_easy_perform(curl);
        
        if(res == CURLE_OK) {
            // Parse JSON response
            struct json_object *parsed_json;
            struct json_object *tag_name;
            
            parsed_json = json_tokener_parse(update_data.data);
            
            if (json_object_object_get_ex(parsed_json, "tag_name", &tag_name)) {
                const char *latest_version = json_object_get_string(tag_name);
                
                // Remove 'v' prefix if present
                if (latest_version[0] == 'v') {
                    latest_version++;
                }
                
                // Compare versions
                if (strcmp(latest_version, APP_VERSION) > 0) {
                    GtkWidget *dialog = gtk_message_dialog_new(NULL,
                        GTK_DIALOG_MODAL,
                        GTK_MESSAGE_INFO,
                        GTK_BUTTONS_YES_NO,
                        "Tersedia update baru (v%s). Versi Anda saat ini v%s.\n\nApakah Anda ingin mengunduh update terbaru?",
                        latest_version, APP_VERSION);
                    
                    gtk_window_set_title(GTK_WINDOW(dialog), "Update Tersedia");
                    
                    int result = gtk_dialog_run(GTK_DIALOG(dialog));
                    if (result == GTK_RESPONSE_YES) {
                        // Open download URL in browser
                        struct json_object *html_url;
                        if (json_object_object_get_ex(parsed_json, "html_url", &html_url)) {
                            const char *download_url = json_object_get_string(html_url);
                            char command[2048];
                            
                            #ifdef _WIN32
                            sprintf(command, "start %s", download_url);
                            #elif __APPLE__
                            sprintf(command, "open %s", download_url);
                            #else
                            sprintf(command, "xdg-open %s", download_url);
                            #endif
                            
                            system(command);
                        }
                    }
                    
                    gtk_widget_destroy(dialog);
                }
                
                json_object_put(parsed_json);
            }
        } else {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    
    curl_global_cleanup();
    free(update_data.data);
}

// Fungsi untuk membuat tab URL Check
GtkWidget* create_url_check_tab(AppWidgets *widgets) {
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 20);
    
    // URL Entry
    GtkWidget *url_label = gtk_label_new("URL yang akan diperiksa:");
    gtk_widget_set_halign(url_label, GTK_ALIGN_START);
    
    widgets->url_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(widgets->url_entry), "Masukkan URL di sini...");
    gtk_widget_set_hexpand(widgets->url_entry, TRUE);
    
    GtkWidget *check_url_button = gtk_button_new_with_label("Periksa URL");
    g_signal_connect(check_url_button, "clicked", G_CALLBACK(on_check_url_clicked), widgets);
    
    // Result Label
    widgets->url_result_label = gtk_label_new("");
    gtk_label_set_selectable(GTK_LABEL(widgets->url_result_label), TRUE);
    
    // Banner image - shield icon
    GtkWidget *banner = gtk_image_new_from_icon_name("security-high", GTK_ICON_SIZE_DIALOG);
    gtk_widget_set_margin_bottom(banner, 20);
    
    // Banner label
    GtkWidget *banner_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(banner_label), 
        "<span font_weight='bold' font_size='large'>URL Phishing Detector</span>");
    gtk_widget_set_margin_bottom(banner_label, 10);
    
    // Info label
    GtkWidget *info_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(info_label), 
        "<span font_style='italic'>Scan URL untuk memeriksa apakah URL tersebut mencurigakan dan berpotensi phishing.</span>");
    gtk_widget_set_margin_bottom(info_label, 20);
    
    // Layout
    gtk_grid_attach(GTK_GRID(grid), banner, 0, 0, 3, 1);
    gtk_grid_attach(GTK_GRID(grid), banner_label, 0, 1, 3, 1);
    gtk_grid_attach(GTK_GRID(grid), info_label, 0, 2, 3, 1);
    gtk_grid_attach(GTK_GRID(grid), url_label, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), widgets->url_entry, 1, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), check_url_button, 2, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), widgets->url_result_label, 0, 4, 3, 1);
    
    return grid;
}

// Fungsi untuk membuat tab File Check
// Fungsi untuk membuat tab File Check (lanjutan)
GtkWidget* create_file_check_tab(AppWidgets *widgets) {
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 20);

    // File Chooser
    GtkWidget *file_label = gtk_label_new("File yang akan diperiksa:");
    gtk_widget_set_halign(file_label, GTK_ALIGN_START);

    widgets->file_chooser_button = gtk_file_chooser_button_new("Pilih File", GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_widget_set_hexpand(widgets->file_chooser_button, TRUE);

    GtkWidget *check_file_button = gtk_button_new_with_label("Periksa File");
    g_signal_connect(check_file_button, "clicked", G_CALLBACK(on_check_file_clicked), widgets);

    // Result Label
    widgets->file_result_label = gtk_label_new("");
    gtk_label_set_selectable(GTK_LABEL(widgets->file_result_label), TRUE);

    // Banner image
    GtkWidget *banner = gtk_image_new_from_icon_name("document-send", GTK_ICON_SIZE_DIALOG);
    gtk_widget_set_margin_bottom(banner, 20);

    // Banner label
    GtkWidget *banner_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(banner_label), 
        "<span font_weight='bold' font_size='large'>File Malware Detector</span>");
    gtk_widget_set_margin_bottom(banner_label, 10);

    // Info label
    GtkWidget *info_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(info_label), 
        "<span font_style='italic'>Scan file untuk memeriksa apakah file tersebut mengandung malware atau konten berbahaya.</span>");
    gtk_widget_set_margin_bottom(info_label, 20);

    // Layout
    gtk_grid_attach(GTK_GRID(grid), banner, 0, 0, 3, 1);
    gtk_grid_attach(GTK_GRID(grid), banner_label, 0, 1, 3, 1);
    gtk_grid_attach(GTK_GRID(grid), info_label, 0, 2, 3, 1);
    gtk_grid_attach(GTK_GRID(grid), file_label, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), widgets->file_chooser_button, 1, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), check_file_button, 2, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), widgets->file_result_label, 0, 4, 3, 1);

    return grid;
}

// Fungsi untuk membuat tab Directory Scan
GtkWidget* create_directory_scan_tab(AppWidgets *widgets) {
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 20);

    // Directory Chooser
    GtkWidget *dir_label = gtk_label_new("Direktori yang akan di-scan:");
    gtk_widget_set_halign(dir_label, GTK_ALIGN_START);

    widgets->dir_chooser_button = gtk_file_chooser_button_new("Pilih Direktori", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER);
    gtk_widget_set_hexpand(widgets->dir_chooser_button, TRUE);

    GtkWidget *scan_button = gtk_button_new_with_label("Mulai Scan");
    g_signal_connect(scan_button, "clicked", G_CALLBACK(on_scan_directory_clicked), widgets);

    // Result Textview
    widgets->dir_result_textview = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(widgets->dir_result_textview), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(widgets->dir_result_textview), GTK_WRAP_WORD);
    
    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scrolled_window), widgets->dir_result_textview);

    widgets->dir_result_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->dir_result_textview));

    // Progress Bar
    widgets->scan_progress = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(widgets->scan_progress), TRUE);

    // Layout
    gtk_grid_attach(GTK_GRID(grid), dir_label, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), widgets->dir_chooser_button, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), scan_button, 2, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), scrolled_window, 0, 1, 3, 1);
    gtk_grid_attach(GTK_GRID(grid), widgets->scan_progress, 0, 2, 3, 1);

    return grid;
}

// Fungsi untuk membuat menu
GtkWidget* create_menu_bar(AppWidgets *widgets) {
    GtkWidget *menu_bar = gtk_menu_bar_new();
    
    // Menu File
    GtkWidget *file_menu = gtk_menu_new();
    GtkWidget *file_item = gtk_menu_item_new_with_label("File");
    GtkWidget *exit_item = gtk_menu_item_new_with_label("Keluar");
    gtk_menu_shell_append(GTK_MENU_SHELL(file_menu), exit_item);
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(file_item), file_menu);
    
    // Menu Help
    GtkWidget *help_menu = gtk_menu_new();
    GtkWidget *help_item = gtk_menu_item_new_with_label("Bantuan");
    GtkWidget *about_item = gtk_menu_item_new_with_label("Tentang");
    GtkWidget *update_item = gtk_menu_item_new_with_label("Periksa Update");
    gtk_menu_shell_append(GTK_MENU_SHELL(help_menu), about_item);
    gtk_menu_shell_append(GTK_MENU_SHELL(help_menu), update_item);
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(help_item), help_menu);
    
    // Signal connections
    g_signal_connect(exit_item, "activate", G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect(about_item, "activate", G_CALLBACK(show_about_dialog), widgets);
    g_signal_connect(update_item, "activate", G_CALLBACK(check_for_updates), NULL);
    
    // Add to menu bar
    gtk_menu_shell_append(GTK_MENU_SHELL(menu_bar), file_item);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu_bar), help_item);
    
    return menu_bar;
}

// Fungsi utama untuk membuat window
void activate(GtkApplication *app, gpointer user_data) {
    AppWidgets *widgets = g_new(AppWidgets, 1);
    
    // Create main window
    widgets->window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(widgets->window), "Phishing & Malware Detector");
    gtk_window_set_default_size(GTK_WINDOW(widgets->window), 800, 600);
    
    // Create main container
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(widgets->window), vbox);
    
    // Create menu
    GtkWidget *menu_bar = create_menu_bar(widgets);
    gtk_box_pack_start(GTK_BOX(vbox), menu_bar, FALSE, FALSE, 0);
    
    // Create notebook (tab container)
    widgets->notebook = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(vbox), widgets->notebook, TRUE, TRUE, 0);
    
    // Create tabs
    GtkWidget *url_tab = create_url_check_tab(widgets);
    GtkWidget *file_tab = create_file_check_tab(widgets);
    GtkWidget *dir_tab = create_directory_scan_tab(widgets);
    
    // Add tabs to notebook
    gtk_notebook_append_page(GTK_NOTEBOOK(widgets->notebook), url_tab, gtk_label_new("URL Check"));
    gtk_notebook_append_page(GTK_NOTEBOOK(widgets->notebook), file_tab, gtk_label_new("File Check"));
    gtk_notebook_append_page(GTK_NOTEBOOK(widgets->notebook), dir_tab, gtk_label_new("Directory Scan"));
    
    // Status bar
    widgets->status_bar = gtk_statusbar_new();
    gtk_box_pack_end(GTK_BOX(vbox), widgets->status_bar, FALSE, FALSE, 0);
    
    // Show all widgets
    gtk_widget_show_all(widgets->window);
    
    // Check for updates on startup
    check_for_updates();
}

int main(int argc, char **argv) {
    GtkApplication *app = gtk_application_new("com.pelajaran.phishingdetector", G_APPLICATION_FLAGS_NONE);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    
    return status;
}
