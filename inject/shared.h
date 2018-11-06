/* Print Error, and Quit */
#define BUG(message, ...)	do { fprintf(stderr, "%s:%s:%d: " message "\n", "BUG", __func__, __LINE__, ##__VA_ARGS__); exit(1); } while(0)
#define BUG_ON(expr, message, ...)	do { if(expr) { fprintf(stderr, "%s:%s:%d: " message "\n", "BUG", __func__, __LINE__, ##__VA_ARGS__); exit(1); } } while(0)
#define BUG_ON_PERROR(expr, message, ...) do { if(expr) { fprintf(stderr, "%s:%s:%d:%s " message "\n", "BUG", __func__, __LINE__, strerror(errno), ##__VA_ARGS__); exit(1); } } while(0)

#define WARN(message, ...)	do { fprintf(stderr, "%s:%s:%d: " message "\n", "BUG", __func__, __LINE__, ##__VA_ARGS__); } while(0)
#define WARN_ON(expr, message, ...)	do { if(expr) { fprintf(stderr, "%s:%s:%d: " message "\n", "BUG", __func__, __LINE__, ##__VA_ARGS__); } } while(0)
#define WARN_ON_PERROR(expr, message, ...) do { if(expr) { fprintf(stderr, "%s:%s:%d:%s " message "\n", "BUG", __func__, __LINE__, strerror(errno), ##__VA_ARGS__); } } while(0)

#define TITUS_PID_1_DIR	"TITUS_PID_1_DIR"
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
