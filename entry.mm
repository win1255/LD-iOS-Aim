#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <stdint.h>
#import <string.h>

// ============================================================
// LD-iOS 插件 v0.3 —— A镜（恐龙属性面板）
// 相对 v0.2 的修复：
//   1) 去掉 CoreGraphics 外部依赖（CGPointZero/CGRectInset 改为内联等价，
//      编译依赖与 v0.1 完全一致：UIKit+Foundation+libc++，排除重签/dyld 加载差异）
//   2) 弹窗先行：constructor 只做 v0.1 同款弹窗（实测成功过），A镜面板延迟 2 秒再启动
//   3) 全程 @try 保护：任何一步异常都不影响弹窗出现
// 数据来源：直接内存读取（IDA 9.4 分析 ShooterGame 1.10192 iOS arm64）
// 引擎锚点：
//   GEngine = *(uintptr_t*)0x105D80720（GetGameWorld 实现直读，已确认）
//   UWorld  = *(UWorld**)(GEngine + 0x780)（当前世界；兜底 WorldList+0x280）
//   ULevel  = *(ULevel**)(World + 0x1d0)（PersistentLevel，FProperty 反解）
//   Actors  = ULevel 内 TArray<AActor*>（运行时启发式定位）
// 恐龙字段：APrimalDinoCharacter（iOS 64 位偏移，ios_analysis5.txt）
// ============================================================

#define GENGINE_ADDR     0x105D80720ULL
#define WORLD_OFF        0x780ULL
#define WL_DATA_OFF      0xC30ULL   // WorldList TArray Data
#define WL_NUM_OFF       0xC38ULL   // WorldList Num
#define WL_WORLD_OFF     0x280ULL   // FWorldContext.World
#define PERSISTENT_LEVEL 0x1D0ULL

#define DINO_HEALTH    0x92C  // float ReplicatedCurrentHealth
#define DINO_MAXHEALTH 0x930  // float ReplicatedMaxHealth
#define DINO_TORPOR    0x934  // float ReplicatedCurrentTorpor
#define DINO_MAXTORPOR 0x938  // float ReplicatedMaxTorpor
#define DINO_NAME      0xC88  // FString DescriptiveName
#define DINO_STATUS    0xD80  // APrimalCharacterStatusComponent*

#define ST_CUR        0x77C  // TArray<float> CurrentStatusValues
#define ST_BASELEVEL  0x6C8  // int BaseCharacterLevel
#define ST_EXTRALEVEL 0x6CC  // int ExtraCharacterLevel

// ---------- 内存读取（全部带防护） ----------
static inline uintptr_t rd64(uintptr_t a) {
    if (a < 0x100000000ULL || a > 0x2000000000ULL) return 0;
    return *(volatile uintptr_t *)a;
}
static inline float rdF(uintptr_t a) {
    if (a < 0x100000000ULL || a > 0x2000000000ULL) return 0;
    return *(volatile float *)a;
}
static inline int rdI(uintptr_t a) {
    if (a < 0x100000000ULL || a > 0x2000000000ULL) return 0;
    return *(volatile int *)a;
}

// ---------- 引擎对象获取 ----------
static uintptr_t getWorld(void) {
    uintptr_t g = rd64(GENGINE_ADDR);
    if (!g) return 0;
    uintptr_t w = rd64(g + WORLD_OFF);
    if (w) return w;
    uintptr_t *list = (uintptr_t *)rd64(g + WL_DATA_OFF);
    int num = rdI(g + WL_NUM_OFF);
    if (list && num > 0 && num < 64) {
        for (int i = 0; i < num; i++) {
            uintptr_t ctx = (uintptr_t)list[i];
            if (!ctx) continue;
            uintptr_t w2 = rd64(ctx + WL_WORLD_OFF);
            if (w2) return w2;
        }
    }
    return 0;
}

static uintptr_t getLevel(uintptr_t world) {
    if (!world) return 0;
    return rd64(world + PERSISTENT_LEVEL);
}

// Actors TArray 启发式定位：ULevel 中第一个"数据指针有效+Num合理"的 TArray
static int getActors(uintptr_t level, uintptr_t *outBuf, int maxOut) {
    if (!level) return 0;
    for (uintptr_t off = 0x80; off < 0x260; off += 8) {
        uintptr_t data = rd64(level + off);
        if (!data || data < 0x100000000ULL) continue;
        int num = rdI(level + off + 8);
        int max = rdI(level + off + 12);
        if (num < 0 || num > 300000 || max < num || max > 300000) continue;
        if (num > 0) {
            uintptr_t first = rd64(data);
            if (!first) continue;
            uintptr_t vt = rd64(first);
            if (vt < 0x100000000ULL || vt > 0x106000000ULL) continue; // vtable 须在二进制内
        }
        int n = num < maxOut ? num : maxOut;
        for (int i = 0; i < n; i++) outBuf[i] = rd64(data + (uintptr_t)i * 8);
        return n;
    }
    return 0;
}

// 恐龙判断：特征启发式（健康字段合理 + 属性组件指针有效 + 属性数组合理）
static int isDino(uintptr_t obj) {
    if (!obj) return 0;
    uintptr_t vt = rd64(obj);
    if (vt < 0x100000000ULL || vt > 0x106000000ULL) return 0;
    float h = rdF(obj + DINO_HEALTH);
    float mh = rdF(obj + DINO_MAXHEALTH);
    if (!(h >= -1e9f && h <= 1e9f)) return 0;
    if (!(mh >= -1e9f && mh <= 1e9f)) return 0;
    if (h <= 0 && mh <= 0) return 0;
    uintptr_t st = rd64(obj + DINO_STATUS);
    if (!st) return 0;
    uintptr_t stvt = rd64(st);
    if (stvt < 0x100000000ULL || stvt > 0x106000000ULL) return 0;
    uintptr_t cur = rd64(st + ST_CUR);
    int ncur = rdI(st + ST_CUR + 8);
    if (ncur < 0 || ncur > 64) return 0;
    if (ncur > 0 && (!cur || cur < 0x100000000ULL)) return 0;
    return 1;
}

// 读名字（FString：Data 指针 + 长度；先按 UTF-16 后按 UTF-8）
static NSString *readName(uintptr_t obj) {
    if (!obj) return @"";
    uintptr_t data = rd64(obj + DINO_NAME);
    int len = rdI(obj + DINO_NAME + 8);
    if (!data || len <= 0 || len > 200) return @"";
    if (len >= 2) {
        unichar u[220];
        memcpy(u, (void *)data, (size_t)len * 2);
        NSString *s = [NSString stringWithCharacters:u length:(NSUInteger)len];
        if (s.length) return s;
    }
    char buf[220];
    memcpy(buf, (void *)data, (size_t)len);
    buf[len < 219 ? len : 219] = 0;
    NSString *s2 = [NSString stringWithUTF8String:buf];
    return s2.length ? s2 : @"";
}

// ---------- A镜面板 UI ----------
@interface LDPanelHelper : NSObject
+ (LDPanelHelper *)shared;
- (void)pan:(UIPanGestureRecognizer *)gr;
@end
static LDPanelHelper *g_helper = nil;
@implementation LDPanelHelper
+ (LDPanelHelper *)shared {
    if (!g_helper) g_helper = [[LDPanelHelper alloc] init];
    return g_helper;
}
- (void)pan:(UIPanGestureRecognizer *)gr {
    UIView *v = gr.view;
    if (!v) return;
    CGPoint t = [gr translationInView:v.superview];
    v.center = CGPointMake(v.center.x + t.x, v.center.y + t.y);
    [gr setTranslation:CGPointMake(0, 0) inView:v.superview];
}
@end

static UIView    *g_panel = nil;
static UILabel   *g_label = nil;
static dispatch_source_t g_timer = nil;

static void updatePanel(void) {
    @try {
        if (!g_label) return;
        uintptr_t world = getWorld();
        uintptr_t level = getLevel(world);
        uintptr_t actors[1024];
        int n = getActors(level, actors, 1024);
        uintptr_t dino = 0;
        for (int i = 0; i < n; i++) {
            if (isDino(actors[i])) { dino = actors[i]; break; }
        }
        if (!dino) {
            g_label.text = @"A镜：未找到恐龙（进游戏后自动检测）";
            return;
        }
        float hp  = rdF(dino + DINO_HEALTH);
        float mhp = rdF(dino + DINO_MAXHEALTH);
        float tp  = rdF(dino + DINO_TORPOR);
        float mtp = rdF(dino + DINO_MAXTORPOR);
        uintptr_t st = rd64(dino + DINO_STATUS);
        int blv = rdI(st + ST_BASELEVEL);
        int elv = rdI(st + ST_EXTRALEVEL);
        float *cur = (float *)rd64(st + ST_CUR);
        int ncur = rdI(st + ST_CUR + 8);
        float stamina = ncur > 1 ? cur[1] : 0;
        float oxygen  = ncur > 3 ? cur[3] : 0;
        float food    = ncur > 4 ? cur[4] : 0;
        float weight  = ncur > 7 ? cur[7] : 0;
        float melee   = ncur > 8 ? cur[8] : 0;
        float speed   = ncur > 9 ? cur[9] : 0;
        NSString *name = readName(dino);
        NSString *txt = [NSString stringWithFormat:
            @"A镜 | %@\n等级 Lv.%d\n\n生命 %d / %d\n眩晕 %d / %d\n耐力 %.1f\n氧气 %.1f\n食物 %.1f\n负重 %.1f\n近战 %.0f%%\n速度 %.0f%%",
            name, blv + elv,
            (int)hp, (int)mhp, (int)tp, (int)mtp,
            stamina, oxygen, food, weight, melee * 100.0f, speed * 100.0f];
        g_label.text = txt;
    } @catch (NSException *e) {
        NSLog(@"[LD] updatePanel exception: %@", e);
    }
}

static void startAim(void) {
    @try {
        if (g_panel) return;
        UIWindow *win = nil;
        if (@available(iOS 13.0, *)) {
            NSArray *scenes = [UIApplication sharedApplication].connectedScenes.allObjects;
            if (scenes.count) {
                UIWindowScene *ws = scenes.firstObject;
                for (UIWindow *w in ws.windows) { if (w.isKeyWindow) { win = w; break; } }
                if (!win && ws.windows.count) win = ws.windows.firstObject;
            }
        }
        if (!win) win = [[UIApplication sharedApplication] keyWindow];
        if (!win) { NSLog(@"[LD] startAim: no window"); return; }

        CGFloat W = win.bounds.size.width;
        g_panel = [[UIView alloc] initWithFrame:CGRectMake(W - 255, 90, 245, 300)];
        g_panel.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.72];
        g_panel.layer.cornerRadius = 12;
        g_panel.layer.borderWidth = 1;
        g_panel.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.35].CGColor;
        g_panel.userInteractionEnabled = YES;

        CGRect lf = CGRectMake(10, 10, g_panel.bounds.size.width - 20, g_panel.bounds.size.height - 20);
        g_label = [[UILabel alloc] initWithFrame:lf];
        g_label.numberOfLines = 0;
        g_label.font = [UIFont systemFontOfSize:13];
        g_label.textColor = [UIColor whiteColor];
        g_label.text = @"A镜：未找到恐龙（进游戏后自动检测）";
        [g_panel addSubview:g_label];

        // 可拖动
        UIPanGestureRecognizer *drag = [[UIPanGestureRecognizer alloc] initWithTarget:[LDPanelHelper shared] action:@selector(pan:)];
        [g_panel addGestureRecognizer:drag];

        [win addSubview:g_panel];
        [win bringSubviewToFront:g_panel];

        g_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
        dispatch_source_set_timer(g_timer, dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), 0.5 * NSEC_PER_SEC, 0.05 * NSEC_PER_SEC);
        dispatch_source_set_event_handler(g_timer, ^{ updatePanel(); });
        dispatch_resume(g_timer);
        NSLog(@"[LD] A镜 panel started");
    } @catch (NSException *e) {
        NSLog(@"[LD] startAim exception: %@", e);
    }
}

__attribute__((constructor))
static void ld_init() {
    NSLog(@"[LD-iOS] 注入成功 v0.3 A镜版");
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            // 弹窗先行（v0.1 同款窗口获取逻辑，实测成功）
            UIWindow *win = nil;
            if (@available(iOS 13.0, *)) {
                NSArray *scenes = [UIApplication sharedApplication].connectedScenes.allObjects;
                if (scenes.count) {
                    id ws = scenes.firstObject;
                    if ([ws isKindOfClass:[UIWindowScene class]]) {
                        UIWindowScene *s = (UIWindowScene *)ws;
                        win = s.keyWindow;
                        if (!win && s.windows.count) win = s.windows.firstObject;
                    }
                }
            }
            if (!win) win = [[UIApplication sharedApplication] keyWindow];
            if (!win) { NSLog(@"[LD] ld_init: no window, bail"); return; }
            UIViewController *vc = win.rootViewController;
            if (!vc) { NSLog(@"[LD] ld_init: no rootVC, bail"); return; }

            UIAlertController *a = [UIAlertController alertControllerWithTitle:@"LD-iOS A镜 v0.3"
                                                                       message:@"注入成功（A镜面板 2 秒后启动）"
                                                                preferredStyle:UIAlertControllerStyleAlert];
            [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
            [vc presentViewController:a animated:YES completion:nil];
            NSLog(@"[LD] alert shown, scheduling A镜 in 2s");

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                startAim();
                NSLog(@"[LD] startAim returned");
            });
        } @catch (NSException *e) {
            NSLog(@"[LD] ld_init exception: %@", e);
        }
    });
}
