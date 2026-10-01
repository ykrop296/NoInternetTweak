// NoInternet.m — v2.1
// Стабильный твик для LiveContainer — полностью имитирует отсутствие интернета.
//
// Ключевые изменения:
//   1. Спуфинг Reachability (SystemConfiguration) — SCNetworkReachabilityGetFlags
//      всегда возвращает 0 (Not Reachable). Приложения думают, что Wi-Fi выключен.
//   2. Спуфинг Network.framework — nw_path_get_status возвращает nw_path_status_unsatisfied.
//   3. Перехват через NSURLProtocol — все HTTP/HTTPS запросы возвращают
//      ошибку NSURLErrorNotConnectedToInternet (-1009).
//   4. Инжект протокола во все NSURLSessionConfiguration (default, ephemeral, background).
//   5. Очистка NSURLCache при запуске приложения (удаляет кэш проверки обновлений).
//   6. УБРАН хук socket() — предотвращает падения TikTok, Spotify и других приложений.
//   7. BSD connect() возвращает ENETDOWN (только для внешних адресов; localhost разрешён).
//   8. DNS getaddrinfo/gethostbyname возвращают ошибку для всех внешних хостов.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <Network/Network.h>
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
// MARK: - Проверка локальных адресов (localhost / loopback / unix)
// ============================================================================

static bool is_local_address(const struct sockaddr *addr) {
    if (!addr) return false;
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
        uint32_t ip = ntohl(addr4->sin_addr.s_addr);
        return (ip >> 24) == 127; // 127.0.0.0/8
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
        return IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr);
    }
    return false;
}

static bool is_local_or_unix(const struct sockaddr *addr) {
    if (!addr) return false;
    if (addr->sa_family == AF_UNIX || addr->sa_family == AF_LOCAL) return true;
    return is_local_address(addr);
}

static bool is_local_host(const char *name) {
    if (!name) return false;
    return (strcmp(name, "localhost") == 0 ||
            strcmp(name, "127.0.0.1") == 0 ||
            strcmp(name, "::1") == 0 ||
            strcmp(name, "0.0.0.0") == 0);
}

// ============================================================================
// MARK: - 1. Спуфинг Reachability (SystemConfiguration.framework)
// Подавляющее большинство приложений перед проверкой обновлений проверяют Reachability.
// ============================================================================

static Boolean (*orig_SCNetworkReachabilityGetFlags)(SCNetworkReachabilityRef, SCNetworkReachabilityFlags *);
static Boolean (*orig_SCNetworkReachabilitySetCallback)(SCNetworkReachabilityRef, SCNetworkReachabilityCallBack, SCNetworkReachabilityContext *);
static Boolean (*orig_SCNetworkReachabilityScheduleWithRunLoop)(SCNetworkReachabilityRef, CFRunLoopRef, CFStringRef);

static SCNetworkReachabilityCallBack g_reachabilityCallback = NULL;
static void *g_reachabilityContextInfo = NULL;

static Boolean hooked_SCNetworkReachabilityGetFlags(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags *flags) {
    if (flags) {
        *flags = 0; // Флаги 0 означают Not Reachable (нет сети)
    }
    NOINTERNET_LOG(@"SCNetworkReachabilityGetFlags() -> 0 (Not Reachable)");
    return TRUE;
}

static Boolean hooked_SCNetworkReachabilitySetCallback(SCNetworkReachabilityRef target,
                                                       SCNetworkReachabilityCallBack callout,
                                                       SCNetworkReachabilityContext *context) {
    g_reachabilityCallback = callout;
    g_reachabilityContextInfo = (context && context->info) ? context->info : NULL;
    if (orig_SCNetworkReachabilitySetCallback) {
        return orig_SCNetworkReachabilitySetCallback(target, callout, context);
    }
    return TRUE;
}

static Boolean hooked_SCNetworkReachabilityScheduleWithRunLoop(SCNetworkReachabilityRef target,
                                                               CFRunLoopRef runLoop,
                                                               CFStringRef runLoopMode) {
    Boolean res = TRUE;
    if (orig_SCNetworkReachabilityScheduleWithRunLoop) {
        res = orig_SCNetworkReachabilityScheduleWithRunLoop(target, runLoop, runLoopMode);
    }
    // Асинхронно уведомляем приложение о том, что сеть недоступна (flags = 0)
    if (g_reachabilityCallback) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (g_reachabilityCallback) {
                g_reachabilityCallback(target, 0, g_reachabilityContextInfo);
            }
        });
    }
    return res;
}

// ============================================================================
// MARK: - 2. Спуфинг Network.framework (iOS 12+)
// NWPathMonitor используется современными приложениями и Alamofire в Swift.
// ============================================================================

static nw_path_status_t (*orig_nw_path_get_status)(nw_path_t);
static nw_path_status_t hooked_nw_path_get_status(nw_path_t path) {
    NOINTERNET_LOG(@"nw_path_get_status() -> nw_path_status_unsatisfied (2)");
    return nw_path_status_unsatisfied; // 2
}

static bool (*orig_nw_path_is_expensive)(nw_path_t);
static bool hooked_nw_path_is_expensive(nw_path_t path) {
    return false;
}

static bool (*orig_nw_path_is_constrained)(nw_path_t);
static bool hooked_nw_path_is_constrained(nw_path_t path) {
    return false;
}

// ============================================================================
// MARK: - 3. BSD Sockets (БЕЗ socket() — крашил Spotify/TikTok!)
// ============================================================================

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);

static int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!addr || is_local_or_unix(addr)) {
        return orig_connect(sockfd, addr, addrlen);
    }

    if (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) {
        NOINTERNET_LOG(@"BLOCKED connect() to external address");
        errno = ENETDOWN; // Сеть отключена
        return -1;
    }

    return orig_connect(sockfd, addr, addrlen);
}

static ssize_t hooked_sendto(int sockfd, const void *buf, size_t len, int flags,
                              const struct sockaddr *dest_addr, socklen_t addrlen) {
    if (dest_addr && !is_local_or_unix(dest_addr) &&
        (dest_addr->sa_family == AF_INET || dest_addr->sa_family == AF_INET6)) {
        NOINTERNET_LOG(@"BLOCKED sendto() to external address");
        errno = ENETDOWN;
        return -1;
    }
    return orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

// ============================================================================
// MARK: - 4. DNS хуки
// ============================================================================

static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static struct hostent *(*orig_gethostbyname)(const char *);
static struct hostent *(*orig_gethostbyname2)(const char *, int);

static int hooked_getaddrinfo(const char *node, const char *service,
                               const struct addrinfo *hints,
                               struct addrinfo **res) {
    if (is_local_host(node)) {
        return orig_getaddrinfo(node, service, hints, res);
    }
    NOINTERNET_LOG(@"BLOCKED getaddrinfo() for: %s", node ? node : "(null)");
    return EAI_NONAME;
}

static struct hostent *hooked_gethostbyname(const char *name) {
    if (is_local_host(name)) return orig_gethostbyname(name);
    NOINTERNET_LOG(@"BLOCKED gethostbyname() for: %s", name ? name : "(null)");
    h_errno = HOST_NOT_FOUND;
    return NULL;
}

static struct hostent *hooked_gethostbyname2(const char *name, int af) {
    if (is_local_host(name)) return orig_gethostbyname2(name, af);
    NOINTERNET_LOG(@"BLOCKED gethostbyname2() for: %s", name ? name : "(null)");
    h_errno = HOST_NOT_FOUND;
    return NULL;
}

// ============================================================================
// MARK: - 5. NSURLProtocol — перехват всех HTTP/HTTPS запросов
// ============================================================================

@interface NoInternetURLProtocol : NSURLProtocol
@end

@implementation NoInternetURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *scheme = request.URL.scheme.lowercaseString;
    if (!scheme) return NO;
    if ([scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"]) {
        NSString *host = request.URL.host.lowercaseString;
        if (!host) return YES;
        if ([host isEqualToString:@"localhost"] ||
            [host isEqualToString:@"127.0.0.1"] ||
            [host isEqualToString:@"::1"] ||
            [host isEqualToString:@"0.0.0.0"]) {
            return NO;
        }
        return YES;
    }
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NOINTERNET_LOG(@"BLOCKED URLProtocol: %@", self.request.URL);
    NSError *error = [NSError errorWithDomain:NSURLErrorDomain
                                         code:NSURLErrorNotConnectedToInternet
                                     userInfo:@{
        NSLocalizedDescriptionKey: @"The Internet connection appears to be offline.",
        NSURLErrorFailingURLStringErrorKey: self.request.URL.absoluteString ?: @"",
        NSURLErrorFailingURLErrorKey: self.request.URL ?: [NSURL URLWithString:@""]
    }];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self.client URLProtocol:self didFailWithError:error];
    });
}

- (void)stopLoading {
}

@end

// ============================================================================
// MARK: - 6. Инжект NSURLProtocol в конфигурации сессий
// ============================================================================

static void inject_protocol_classes(NSURLSessionConfiguration *config) {
    if (!config) return;
    NSMutableArray *protocols = [config.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![protocols containsObject:[NoInternetURLProtocol class]]) {
        [protocols insertObject:[NoInternetURLProtocol class] atIndex:0];
        config.protocolClasses = protocols;
    }
}

static void swizzle_class_method(Class cls, SEL orig, SEL swiz) {
    Class meta = object_getClass((id)cls);
    Method origM = class_getInstanceMethod(meta, orig);
    Method swizM = class_getInstanceMethod(meta, swiz);
    if (origM && swizM) {
        method_exchangeImplementations(origM, swizM);
    }
}

static void swizzle_instance_method(Class cls, SEL orig, SEL swiz) {
    Method origM = class_getInstanceMethod(cls, orig);
    Method swizM = class_getInstanceMethod(cls, swiz);
    if (!origM || !swizM) return;

    if (class_addMethod(cls, orig,
                        method_getImplementation(swizM),
                        method_getTypeEncoding(swizM))) {
        class_replaceMethod(cls, swiz,
                            method_getImplementation(origM),
                            method_getTypeEncoding(origM));
    } else {
        method_exchangeImplementations(origM, swizM);
    }
}

@interface NSURLSessionConfiguration (NoInternet)
@end

@implementation NSURLSessionConfiguration (NoInternet)

+ (NSURLSessionConfiguration *)ni_defaultSessionConfiguration {
    NSURLSessionConfiguration *config = [self ni_defaultSessionConfiguration];
    inject_protocol_classes(config);
    return config;
}

+ (NSURLSessionConfiguration *)ni_ephemeralSessionConfiguration {
    NSURLSessionConfiguration *config = [self ni_ephemeralSessionConfiguration];
    inject_protocol_classes(config);
    return config;
}

+ (NSURLSessionConfiguration *)ni_backgroundSessionConfigurationWithIdentifier:(NSString *)identifier {
    NSURLSessionConfiguration *config = [self ni_backgroundSessionConfigurationWithIdentifier:identifier];
    inject_protocol_classes(config);
    return config;
}

- (void)ni_setProtocolClasses:(NSArray<Class> *)classes {
    NSMutableArray *protocols = [classes mutableCopy] ?: [NSMutableArray array];
    if (![protocols containsObject:[NoInternetURLProtocol class]]) {
        [protocols insertObject:[NoInternetURLProtocol class] atIndex:0];
    }
    [self ni_setProtocolClasses:protocols];
}

@end

@interface NSURLSession (NoInternetInjection)
@end

@implementation NSURLSession (NoInternetInjection)

+ (NSURLSession *)ni_sessionWithConfiguration:(NSURLSessionConfiguration *)configuration {
    inject_protocol_classes(configuration);
    return [self ni_sessionWithConfiguration:configuration];
}

+ (NSURLSession *)ni_sessionWithConfiguration:(NSURLSessionConfiguration *)configuration
                                     delegate:(id<NSURLSessionDelegate>)delegate
                                delegateQueue:(NSOperationQueue *)queue {
    inject_protocol_classes(configuration);
    return [self ni_sessionWithConfiguration:configuration delegate:delegate delegateQueue:queue];
}

@end

// ============================================================================
// MARK: - Инициализация (Конструктор при загрузке dylib)
// ============================================================================

__attribute__((constructor))
static void NoInternetInit(void) {
    NOINTERNET_LOG(@"=== NoInternet Tweak v2.1 Loading ===");
    NOINTERNET_LOG(@"Bundle: %@", [[NSBundle mainBundle] bundleIdentifier]);

    // 1. Очистка кэша запросов при запуске (чтобы не брались закэшированные проверки обновлений)
    [[NSURLCache sharedURLCache] removeAllCachedResponses];

    // 2. Глобальная регистрация NSURLProtocol
    [NSURLProtocol registerClass:[NoInternetURLProtocol class]];

    // 3. Свизлинг фабричных методов NSURLSessionConfiguration
    Class cfgClass = [NSURLSessionConfiguration class];
    swizzle_class_method(cfgClass, @selector(defaultSessionConfiguration), @selector(ni_defaultSessionConfiguration));
    swizzle_class_method(cfgClass, @selector(ephemeralSessionConfiguration), @selector(ni_ephemeralSessionConfiguration));
    swizzle_class_method(cfgClass, @selector(backgroundSessionConfigurationWithIdentifier:), @selector(ni_backgroundSessionConfigurationWithIdentifier:));
    swizzle_instance_method(cfgClass, @selector(setProtocolClasses:), @selector(ni_setProtocolClasses:));

    // 4. Свизлинг фабричных методов NSURLSession
    Class sessClass = [NSURLSession class];
    swizzle_class_method(sessClass, @selector(sessionWithConfiguration:), @selector(ni_sessionWithConfiguration:));
    swizzle_class_method(sessClass, @selector(sessionWithConfiguration:delegate:delegateQueue:), @selector(ni_sessionWithConfiguration:delegate:delegateQueue:));

    // 5. Fishhook: Reachability + Network.framework + BSD сокеты + DNS
    struct rebinding rebindings[] = {
        // SystemConfiguration Reachability (симулируем полное отсутствие сети)
        {"SCNetworkReachabilityGetFlags",             (void *)hooked_SCNetworkReachabilityGetFlags,             (void **)&orig_SCNetworkReachabilityGetFlags},
        {"SCNetworkReachabilitySetCallback",            (void *)hooked_SCNetworkReachabilitySetCallback,            (void **)&orig_SCNetworkReachabilitySetCallback},
        {"SCNetworkReachabilityScheduleWithRunLoop",    (void *)hooked_SCNetworkReachabilityScheduleWithRunLoop,    (void **)&orig_SCNetworkReachabilityScheduleWithRunLoop},

        // Network.framework (NWPathMonitor)
        {"nw_path_get_status",                         (void *)hooked_nw_path_get_status,                         (void **)&orig_nw_path_get_status},
        {"nw_path_is_expensive",                      (void *)hooked_nw_path_is_expensive,                      (void **)&orig_nw_path_is_expensive},
        {"nw_path_is_constrained",                    (void *)hooked_nw_path_is_constrained,                    (void **)&orig_nw_path_is_constrained},

        // BSD сокеты
        {"connect",                                    (void *)hooked_connect,                                    (void **)&orig_connect},
        {"sendto",                                     (void *)hooked_sendto,                                     (void **)&orig_sendto},

        // DNS
        {"getaddrinfo",                                (void *)hooked_getaddrinfo,                                (void **)&orig_getaddrinfo},
        {"gethostbyname",                              (void *)hooked_gethostbyname,                              (void **)&orig_gethostbyname},
        {"gethostbyname2",                             (void *)hooked_gethostbyname2,                             (void **)&orig_gethostbyname2},
    };

    rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
    NOINTERNET_LOG(@"=== v2.1 All hooks installed (Offline mode simulated & traffic blocked) ===");
}
