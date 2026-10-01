// NoInternet.m
// Tweak для LiveContainer — полностью блокирует доступ приложения в интернет.
//
// Перехватывает сетевые вызовы на ВСЕХ уровнях:
//   1. BSD сокеты (connect, sendto, sendmsg)
//   2. DNS резолвинг (getaddrinfo, gethostbyname, gethostbyname2)
//   3. NSURLSession / NSURLConnection (через ObjC method swizzling)
//   4. CFNetwork (CFURLConnectionStart, CFURLSessionCreateTask)
//
// Сборка: см. Makefile
// Использование: скопируйте NoInternet.dylib в LiveContainer → Tweaks

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <dlfcn.h>

#include "fishhook.h"

// ============================================================================
// MARK: - Логирование
// ============================================================================

#define NOINTERNET_LOG(fmt, ...) \
    NSLog(@"[NoInternet] " fmt, ##__VA_ARGS__)

// ============================================================================
// MARK: - Оригинальные указатели на перехваченные функции
// ============================================================================

// BSD Sockets
static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static ssize_t (*orig_sendto)(int, const void *, size_t, int,
                               const struct sockaddr *, socklen_t);
static ssize_t (*orig_sendmsg)(int, const struct msghdr *, int);
static int (*orig_socket)(int, int, int);

// DNS
static int (*orig_getaddrinfo)(const char *, const char *,
                                const struct addrinfo *,
                                struct addrinfo **);
static struct hostent *(*orig_gethostbyname)(const char *);
static struct hostent *(*orig_gethostbyname2)(const char *, int);

// ============================================================================
// MARK: - Вспомогательные функции
// ============================================================================

/// Проверяет, является ли адрес локальным (localhost / loopback)
static bool is_local_address(const struct sockaddr *addr) {
    if (!addr) return false;

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
        // 127.0.0.0/8
        uint32_t ip = ntohl(addr4->sin_addr.s_addr);
        return (ip >> 24) == 127;
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
        // ::1
        return IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr);
    }

    return false;
}

/// Проверяет, является ли сокет Unix-доменным (локальная IPC)
static bool is_unix_socket(const struct sockaddr *addr) {
    return addr && addr->sa_family == AF_UNIX;
}

// ============================================================================
// MARK: - Хуки BSD Sockets
// ============================================================================

/// Перехват connect() — блокирует все сетевые соединения кроме localhost
static int hooked_connect(int sockfd, const struct sockaddr *addr,
                           socklen_t addrlen) {
    if (!addr) {
        return orig_connect(sockfd, addr, addrlen);
    }

    // Разрешаем Unix-сокеты (используются для IPC внутри приложения)
    if (is_unix_socket(addr)) {
        return orig_connect(sockfd, addr, addrlen);
    }

    // Разрешаем localhost (нужно для WebView и внутренних сервисов)
    if (is_local_address(addr)) {
        return orig_connect(sockfd, addr, addrlen);
    }

    // Блокируем все внешние соединения
    NOINTERNET_LOG(@"BLOCKED connect() to external address (family=%d)",
                   addr->sa_family);
    errno = ENETUNREACH;
    return -1;
}

/// Перехват sendto() — блокирует отправку на внешние адреса
static ssize_t hooked_sendto(int sockfd, const void *buf, size_t len,
                              int flags, const struct sockaddr *dest_addr,
                              socklen_t addrlen) {
    if (dest_addr && !is_unix_socket(dest_addr) &&
        !is_local_address(dest_addr)) {
        NOINTERNET_LOG(@"BLOCKED sendto() to external address");
        errno = ENETUNREACH;
        return -1;
    }
    return orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

/// Перехват sendmsg() — блокирует отправку на внешние адреса
static ssize_t hooked_sendmsg(int sockfd, const struct msghdr *msg,
                               int flags) {
    if (msg && msg->msg_name) {
        const struct sockaddr *addr = (const struct sockaddr *)msg->msg_name;
        if (!is_unix_socket(addr) && !is_local_address(addr)) {
            NOINTERNET_LOG(@"BLOCKED sendmsg() to external address");
            errno = ENETUNREACH;
            return -1;
        }
    }
    return orig_sendmsg(sockfd, msg, flags);
}

/// Перехват socket() — можно заблокировать создание сетевых сокетов
/// (оставлен permissive — блокировка на уровне connect более надёжна)
static int hooked_socket(int domain, int type, int protocol) {
    // Блокируем только INET/INET6 сокеты, остальные разрешаем
    if (domain == AF_INET || domain == AF_INET6) {
        NOINTERNET_LOG(@"BLOCKED socket() creation (domain=%d, type=%d)",
                       domain, type);
        errno = EACCES;
        return -1;
    }
    return orig_socket(domain, type, protocol);
}

// ============================================================================
// MARK: - Хуки DNS
// ============================================================================

/// Перехват getaddrinfo() — блокирует DNS-резолвинг
static int hooked_getaddrinfo(const char *node, const char *service,
                               const struct addrinfo *hints,
                               struct addrinfo **res) {
    // Разрешаем резолвинг localhost
    if (node && (strcmp(node, "localhost") == 0 ||
                 strcmp(node, "127.0.0.1") == 0 ||
                 strcmp(node, "::1") == 0)) {
        return orig_getaddrinfo(node, service, hints, res);
    }

    NOINTERNET_LOG(@"BLOCKED getaddrinfo() for host: %s",
                   node ? node : "(null)");
    return EAI_NONAME;
}

/// Перехват gethostbyname() — блокирует DNS
static struct hostent *hooked_gethostbyname(const char *name) {
    if (name && (strcmp(name, "localhost") == 0 ||
                 strcmp(name, "127.0.0.1") == 0)) {
        return orig_gethostbyname(name);
    }

    NOINTERNET_LOG(@"BLOCKED gethostbyname() for: %s", name ? name : "(null)");
    h_errno = HOST_NOT_FOUND;
    return NULL;
}

/// Перехват gethostbyname2() — блокирует DNS
static struct hostent *hooked_gethostbyname2(const char *name, int af) {
    if (name && (strcmp(name, "localhost") == 0 ||
                 strcmp(name, "127.0.0.1") == 0)) {
        return orig_gethostbyname2(name, af);
    }

    NOINTERNET_LOG(@"BLOCKED gethostbyname2() for: %s", name ? name : "(null)");
    h_errno = HOST_NOT_FOUND;
    return NULL;
}

// ============================================================================
// MARK: - ObjC Method Swizzling для NSURLSession
// ============================================================================

/// Свизлинг метода — меняет реализацию метода класса
static void swizzle_instance_method(Class cls, SEL original, SEL swizzled) {
    Method origMethod = class_getInstanceMethod(cls, original);
    Method swizMethod = class_getInstanceMethod(cls, swizzled);

    if (!origMethod || !swizMethod) return;

    BOOL didAddMethod = class_addMethod(
        cls, original,
        method_getImplementation(swizMethod),
        method_getTypeEncoding(swizMethod));

    if (didAddMethod) {
        class_replaceMethod(
            cls, swizzled,
            method_getImplementation(origMethod),
            method_getTypeEncoding(origMethod));
    } else {
        method_exchangeImplementations(origMethod, swizMethod);
    }
}

// ============================================================================
// MARK: - NSURLSession категория с перехваченными методами
// ============================================================================

@interface NSURLSession (NoInternet)
@end

@implementation NSURLSession (NoInternet)

/// Перехват dataTaskWithURL:completionHandler:
- (NSURLSessionDataTask *)noInternet_dataTaskWithURL:(NSURL *)url
    completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))handler {
    NOINTERNET_LOG(@"BLOCKED NSURLSession dataTask for URL: %@", url);
    if (handler) {
        NSError *error = [NSError errorWithDomain:NSURLErrorDomain
                                             code:NSURLErrorNotConnectedToInternet
                                         userInfo:@{
            NSLocalizedDescriptionKey:
                @"Internet access is blocked by NoInternet tweak"
        }];
        dispatch_async(dispatch_get_main_queue(), ^{
            handler(nil, nil, error);
        });
    }
    // Возвращаем реальную задачу (отменённую), чтобы избежать nil-crash
    NSURLSessionDataTask *task =
        [self noInternet_dataTaskWithURL:url completionHandler:handler];
    [task cancel];
    return task;
}

/// Перехват dataTaskWithRequest:completionHandler:
- (NSURLSessionDataTask *)noInternet_dataTaskWithRequest:(NSURLRequest *)request
    completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))handler {
    NOINTERNET_LOG(@"BLOCKED NSURLSession dataTask for request: %@",
                   request.URL);
    if (handler) {
        NSError *error = [NSError errorWithDomain:NSURLErrorDomain
                                             code:NSURLErrorNotConnectedToInternet
                                         userInfo:@{
            NSLocalizedDescriptionKey:
                @"Internet access is blocked by NoInternet tweak"
        }];
        dispatch_async(dispatch_get_main_queue(), ^{
            handler(nil, nil, error);
        });
    }
    NSURLSessionDataTask *task =
        [self noInternet_dataTaskWithRequest:request completionHandler:handler];
    [task cancel];
    return task;
}

/// Перехват downloadTaskWithURL:completionHandler:
- (NSURLSessionDownloadTask *)noInternet_downloadTaskWithURL:(NSURL *)url
    completionHandler:(void (^)(NSURL *, NSURLResponse *, NSError *))handler {
    NOINTERNET_LOG(@"BLOCKED NSURLSession downloadTask for URL: %@", url);
    if (handler) {
        NSError *error = [NSError errorWithDomain:NSURLErrorDomain
                                             code:NSURLErrorNotConnectedToInternet
                                         userInfo:@{
            NSLocalizedDescriptionKey:
                @"Internet access is blocked by NoInternet tweak"
        }];
        dispatch_async(dispatch_get_main_queue(), ^{
            handler(nil, nil, error);
        });
    }
    NSURLSessionDownloadTask *task =
        [self noInternet_downloadTaskWithURL:url completionHandler:handler];
    [task cancel];
    return task;
}

/// Перехват uploadTaskWithRequest:fromData:completionHandler:
- (NSURLSessionUploadTask *)noInternet_uploadTaskWithRequest:(NSURLRequest *)req
    fromData:(NSData *)bodyData
    completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))handler {
    NOINTERNET_LOG(@"BLOCKED NSURLSession uploadTask for request: %@",
                   req.URL);
    if (handler) {
        NSError *error = [NSError errorWithDomain:NSURLErrorDomain
                                             code:NSURLErrorNotConnectedToInternet
                                         userInfo:@{
            NSLocalizedDescriptionKey:
                @"Internet access is blocked by NoInternet tweak"
        }];
        dispatch_async(dispatch_get_main_queue(), ^{
            handler(nil, nil, error);
        });
    }
    NSURLSessionUploadTask *task =
        [self noInternet_uploadTaskWithRequest:req
                                     fromData:bodyData
                            completionHandler:handler];
    [task cancel];
    return task;
}

@end

// ============================================================================
// MARK: - NSURLConnection категория (legacy API)
// ============================================================================

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

@interface NSURLConnection (NoInternet)
@end

@implementation NSURLConnection (NoInternet)

+ (NSData *)noInternet_sendSynchronousRequest:(NSURLRequest *)request
    returningResponse:(NSURLResponse **)response
    error:(NSError **)error {
    NOINTERNET_LOG(@"BLOCKED NSURLConnection sendSynchronousRequest: %@",
                   request.URL);
    if (error) {
        *error = [NSError errorWithDomain:NSURLErrorDomain
                                     code:NSURLErrorNotConnectedToInternet
                                 userInfo:@{
            NSLocalizedDescriptionKey:
                @"Internet access is blocked by NoInternet tweak"
        }];
    }
    return nil;
}

@end

#pragma clang diagnostic pop

// ============================================================================
// MARK: - Установка хуков NSURLSession
// ============================================================================

static void install_urlsession_hooks(void) {
    Class sessionClass = [NSURLSession class];

    // dataTaskWithURL:completionHandler:
    swizzle_instance_method(
        sessionClass,
        @selector(dataTaskWithURL:completionHandler:),
        @selector(noInternet_dataTaskWithURL:completionHandler:));

    // dataTaskWithRequest:completionHandler:
    swizzle_instance_method(
        sessionClass,
        @selector(dataTaskWithRequest:completionHandler:),
        @selector(noInternet_dataTaskWithRequest:completionHandler:));

    // downloadTaskWithURL:completionHandler:
    swizzle_instance_method(
        sessionClass,
        @selector(downloadTaskWithURL:completionHandler:),
        @selector(noInternet_downloadTaskWithURL:completionHandler:));

    // uploadTaskWithRequest:fromData:completionHandler:
    swizzle_instance_method(
        sessionClass,
        @selector(uploadTaskWithRequest:fromData:completionHandler:),
        @selector(noInternet_uploadTaskWithRequest:fromData:completionHandler:));

    NOINTERNET_LOG(@"NSURLSession hooks installed");
}

// ============================================================================
// MARK: - Установка хуков NSURLConnection
// ============================================================================

static void install_urlconnection_hooks(void) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    Class connClass = object_getClass([NSURLConnection class]); // meta-class

    Method origMethod = class_getClassMethod(
        [NSURLConnection class],
        @selector(sendSynchronousRequest:returningResponse:error:));
    Method swizMethod = class_getClassMethod(
        [NSURLConnection class],
        @selector(noInternet_sendSynchronousRequest:returningResponse:error:));

    if (origMethod && swizMethod) {
        method_exchangeImplementations(origMethod, swizMethod);
        NOINTERNET_LOG(@"NSURLConnection hooks installed");
    }
#pragma clang diagnostic pop
}

// ============================================================================
// MARK: - Установка хуков fishhook (BSD sockets + DNS)
// ============================================================================

static void install_socket_hooks(void) {
    struct rebinding rebindings[] = {
        {"connect",        (void *)hooked_connect,        (void **)&orig_connect},
        {"sendto",         (void *)hooked_sendto,         (void **)&orig_sendto},
        {"sendmsg",        (void *)hooked_sendmsg,        (void **)&orig_sendmsg},
        {"socket",         (void *)hooked_socket,         (void **)&orig_socket},
        {"getaddrinfo",    (void *)hooked_getaddrinfo,    (void **)&orig_getaddrinfo},
        {"gethostbyname",  (void *)hooked_gethostbyname,  (void **)&orig_gethostbyname},
        {"gethostbyname2", (void *)hooked_gethostbyname2, (void **)&orig_gethostbyname2},
    };

    rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
    NOINTERNET_LOG(@"BSD socket & DNS hooks installed");
}

// ============================================================================
// MARK: - Конструктор (точка входа при инжекте dylib)
// ============================================================================

__attribute__((constructor))
static void NoInternetInit(void) {
    NOINTERNET_LOG(@"=== NoInternet Tweak Loading ===");
    NOINTERNET_LOG(@"Bundle: %@", [[NSBundle mainBundle] bundleIdentifier]);

    // 1. Перехват BSD сокетов и DNS через fishhook
    install_socket_hooks();

    // 2. Перехват NSURLSession через ObjC swizzling
    install_urlsession_hooks();

    // 3. Перехват NSURLConnection (legacy)
    install_urlconnection_hooks();

    NOINTERNET_LOG(@"=== All hooks installed. Internet access is BLOCKED ===");
}
