#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonCrypto.h>
#import <stdint.h>
#import <string.h>
#import <mach-o/dyld.h>

// ============================================================
// LD-iOS 插件 v0.4a —— 进服主页 + A镜画质（UIKit 两 tab）
// 相对 v0.3 新增：
//   1) 进服主页 tab：链接输入（明文 IP:端口 / Base64+ECB 加密串自动识别）
//      + 粘贴/清除/加入 + 历史记录 + 已保存服务器（增删/点击加入）
//   2) A镜画质 tab：A镜开关（控制属性面板）+ FOV 广角 + 4K/高清/战斗/恢复
//      + 自定义代码输入发送 + 每日/每月礼包按钮
// 引擎调用（iOS 主程序 ShooterGame 1.10192 arm64，基址 0x100000000）：
//   execEngineCmd: sub_1016010A4（命令分发器，主程序连服/孵蛋/放置等均走它，
//                  参数 = FString*，UTF-16）
//   连服命令格式: JoinServer:ip:port（主程序 0x101b054d4 内 "JoinServer:%s:%s"）
//   画质/礼包命令: 同样走 execEngineCmd（r.xxx 渲染参数 / JDARK_GIFT|DAILY）
// 链接解密: Base64 -> AES-256-ECB（key = 安卓同款
//           "IE/sZCes0kqnhGZV3}K3wp6IC7OfHDL"）-> host:port
// 存储: NSUserDefaults（历史/服务器列表/面板位置）
// ============================================================

#define ENGINE_BASE      0x100000000ULL
#define ENGINE_SLIDE     ((uintptr_t)_dyld_get_image_vmaddr_slide(0))
#define CMD_FUNC_OFF     0x16010A4ULL   // sub_1016010A4（命令分发器）
#define AES_KEY          "IE/sZCes0kqnhGZV3}K3wp6IC7OfHDL"

// ---------- A镜锚点（v0.3 已验证） ----------
#define GENGINE_ADDR     0x105D80720ULL
#define WORLD_OFF        0x780ULL
#define WL_DATA_OFF      0xC30ULL
#define WL_NUM_OFF       0xC38ULL
#define WL_WORLD_OFF     0x280ULL
#define PERSISTENT_LEVEL 0x1D0ULL
#define DINO_HEALTH    0x92C
#define DINO_MAXHEALTH 0x930
#define DINO_TORPOR    0x934
#define DINO_MAXTORPOR 0x938
#define DINO_NAME      0xC88
#define DINO_STATUS    0xD80
#define ST_CUR         0x77C
#define ST_BASELEVEL   0x6C8
#define ST_EXTRALEVEL  0x6CC

// ---------- 内存读取 ----------
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
static uintptr_t getLevel(uintptr_t world) { return world ? rd64(world + PERSISTENT_LEVEL) : 0; }

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
            if (vt < 0x100000000ULL || vt > 0x106000000ULL) continue;
        }
        int n = num < maxOut ? num : maxOut;
        for (int i = 0; i < n; i++) outBuf[i] = rd64(data + (uintptr_t)i * 8);
        return n;
    }
    return 0;
}

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
    int ncur = rdI(st + ST_CUR + 8);
    if (ncur < 0 || ncur > 64) return 0;
    return 1;
}

static NSString *readName(uintptr_t obj) {
    if (!obj) return @"";
    uintptr_t data = rd64(obj + DINO_NAME);
    int len = rdI(obj + DINO_NAME + 8);
    if (!data || len <= 0 || len > 200) return @"";
    unichar u[220];
    memcpy(u, (void *)data, (size_t)len * 2);
    NSString *s = [NSString stringWithCharacters:u length:(NSUInteger)len];
    return s.length ? s : @"";
}

// ---------- FString16（UE4 iOS UTF-16 FString 布局：Data + Num + Max） ----------
typedef struct { unichar *Data; int32_t Num; int32_t Max; } FString16;

static FString16 makeFString16(const char *utf8) {
    FString16 fs = {0, 0, 0};
    if (!utf8) return fs;
    NSString *s = [NSString stringWithUTF8String:utf8];
    if (!s) return fs;
    NSUInteger len = s.length;
    unichar *buf = (unichar *)malloc((len + 1) * sizeof(unichar));
    if (!buf) return fs;
    [s getCharacters:buf range:NSMakeRange(0, len)];
    buf[len] = 0;
    fs.Data = buf;
    fs.Num = (int32_t)len;
    fs.Max = (int32_t)(len + 1);
    return fs;
}
static void freeFString16(FString16 *fs) {
    if (fs && fs->Data) { free(fs->Data); fs->Data = NULL; }
}

// ---------- 引擎命令执行（sub_1016010A4，命令分发器） ----------
static void engineExec(const char *cmd) {
    @try {
        if (!cmd || !cmd[0]) return;
        uintptr_t fn = ENGINE_BASE + ENGINE_SLIDE + CMD_FUNC_OFF;
        FString16 fs = makeFString16(cmd);
        if (!fs.Data) return;
        ((void (*)(void *))fn)(&fs);
        freeFString16(&fs);
    } @catch (NSException *e) {
        NSLog(@"[LD] engineExec exception: %@ cmd=%s", e, cmd);
    }
}

// ---------- 链接解析：明文 host:port / Base64+ECB 加密串 ----------
static NSData *aesEcbDecrypt(NSData *data) {
    if (!data || data.length == 0 || (data.length % 16) != 0) return nil;
    NSMutableData *out = [NSMutableData dataWithLength:data.length];
    size_t outLen = data.length;
    CCCryptorStatus st = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionECBMode,
        AES_KEY, 32, NULL,
        data.bytes, data.length,
        out.mutableBytes, outLen, &outLen);
    if (st != kCCSuccess) return nil;
    out.length = outLen;
    return out;
}

static BOOL parseAddressInner(NSString *s, NSString **host, int *port) {
    if (!s.length) return NO;
    NSRange r = [s rangeOfString:@":" options:NSBackwardsSearch];
    if (r.location != NSNotFound && r.location > 0 && r.location < s.length - 1) {
        NSString *h = [s substringToIndex:r.location];
        NSString *p = [s substringFromIndex:r.location + 1];
        int pv = p.intValue;
        if (pv > 0 && pv < 65536 && h.length) {
            *host = h;
            *port = pv;
            return YES;
        }
    }
    return NO;
}

static BOOL parseAddress(NSString *s, NSString **host, int *port) {
    if (!s.length) return NO;
    // 1) 明文 host:port
    if (parseAddressInner(s, host, port)) return YES;
    // 2) Base64 + AES-256-ECB 解密后再解析
    NSData *dec = aesEcbDecrypt([[NSData alloc] initWithBase64EncodedString:s options:0]);
    if (dec) {
        NSString *plain = [[NSString alloc] initWithData:dec encoding:NSUTF8StringEncoding];
        if (plain && ![plain isEqualToString:s] && parseAddressInner(plain, host, port)) return YES;
    }
    return NO;
}

// ---------- NSUserDefaults 存储 ----------
#define HIST_KEY   @"LD_v04_join_history"
#define SRV_KEY    @"LD_v04_server_list"

static NSMutableArray *loadHistory(void) {
    NSArray *a = [[NSUserDefaults standardUserDefaults] arrayForKey:HIST_KEY];
    return a ? [a mutableCopy] : [NSMutableArray array];
}
static void addHistory(NSString *s) {
    if (!s.length) return;
    NSMutableArray *h = loadHistory();
    [h removeObject:s];
    [h insertObject:s atIndex:0];
    while (h.count > 20) [h removeLastObject];
    [[NSUserDefaults standardUserDefaults] setObject:h forKey:HIST_KEY];
}
static NSMutableArray *loadServers(void) {
    NSArray *a = [[NSUserDefaults standardUserDefaults] arrayForKey:SRV_KEY];
    return a ? [a mutableCopy] : [NSMutableArray array];
}
static void saveServers(NSArray *list) {
    [[NSUserDefaults standardUserDefaults] setObject:list forKey:SRV_KEY];
}

// ---------- 画质预设命令（安卓同款） ----------
static const char *g_quality4k = "r.MobileContentScaleFactor 2|r.tonemapper.sharpen 2|r.skylightintensitymultiplier 6|r.water.singleLayer.reflection 0|r.ngx.dlss.enable 1|r.nanite.maxpixelsperedge 5|r.bloomquality 0|r.EyeAdaptationQuality 1|r.fog 0|t.maxfps 0|stat fps";
static const char *g_qualityHD = "r.MobileContentScaleFactor 1.5|r.tonemapper.sharpen 2|r.skylightintensitymultiplier 6|r.water.singleLayer.reflection 0|r.ngx.dlss.enable 0|r.nanite.maxpixelsperedge 2|r.bloomquality 0|r.EyeAdaptationQuality 1|r.fog 0|t.maxfps 0|stat fps";
static const char *g_qualityBattle = "r.ShadowQuality 0|r.AmbientOcclusionLevels 0|r.Fog 0|r.VolumetricFog 0|r.Atmosphere 0|r.LightShafts 0|r.BloomQuality 0|r.DepthOfFieldQuality 0|r.MotionBlurQuality 0|r.SSR.Quality 0|r.ReflectionEnvironment 0|r.TonemapperQuality 0|r.MipMapLODBias 1|grass.enable 0|r.ContactShadows 0|r.DynamicGlobalIlluminationMethod 1|r.Nanite.MaxPixelsPerEdge 1|r.Shadow.CSM.MaxCascades 0|r.Water.SingleLayer.Reflection 0|fx.MaxNiagaraGUParticlesSpawnPerFrame 0|sg.FoliageQuality 0|wp.Runtime.UpdateStreamingSources 0|ShowFlag.Materials 0|FogDensity 0.0|r.SkyAtmosphere 0|r.TrueSkyQuality 0|r.HZBOcclusion 0|r.DetailMode 0|r.PostProcessing.DisableMaterials 1|r.SceneColorFringeQuality 0|r.DefaultFeature.PostProcessing.False|r.DefaultFeature.AutoExposure.False|r.ExposureOffset 1.5|r.SkylightIntensityMultiplier 10|r.DistanceFieldAO 0|slate.contrast 1|foliage.LODDistanceScale .7|r.vsync 1|stat fps|r.Nanite.MaxPixelsPerEdge 4|sg.AntiAliasingQuality 0|sg.ShadowQuality 0|sg.EffectsQuality 0|sg.IBLQuality 0|r.SSAOSmartBlur 0|r.BloomQuality 0|r.DepthOfFieldQuality 0|r.ExposureOffset 0.3|r.Shadow.MaxResolution 2|sg.ResolutionQuality 10|sg.PostProcessQuality 0|sg.TextureQuality 0|sg.TrueSkyQuality 0|sg.GroundCullQuality 0|sg.HighFieldShadowQuality 0|r.EarlyZPass 0|r.SSS.Scale 0|r.SSS.SampleSet 0|r.LensFlareQuality 0|r.MaxAnisotropy 0|r.onerametheheading 1|r.simpledynamiclighting 1|r.LightShaftQuality 0|r.RefractionQuality 0|r.UpsampleQuality 0|grass.sizedensity 0|grass.sizescale 0|r.volumetriccloud 0|postprocessing.disable_motionblur 0|postprocessing.disablematerials 0|r.lumen.reflections.allow 0|r.dynamicglobalilluminationmethod 0|r.MaterialQualityLevel 1|R.streaming.poolsize 0|r.MobileContentScaleFactor 2|r.Tonemapper.Sharpen 2|r.AOOverwriteSceneColor 1|t.maxfps 0";
static const char *g_qualityReset = "r.MobileContentScaleFactor 1.0|r.tonemapper.sharpen 1|r.skylightintensitymultiplier 1|r.water.singleLayer.reflection 1|r.ngx.dlss.enable 0|r.nanite.maxpixelsperedge 3|r.bloomquality 1|r.EyeAdaptationQuality 0|r.fog 1|r.ShadowQuality 2|r.AmbientOcclusionLevels 2|r.VolumetricFog 1|r.Atmosphere 1|r.LightShafts 1|r.BloomQuality 2|r.DepthOfFieldQuality 1|r.MotionBlurQuality 1|r.SSR.Quality 1|r.TonemapperQuality 1|r.MipMapLODBias 0|grass.enable 1|r.ContactShadows 1|r.DynamicGlobalIlluminationMethod 0|r.vsync 0|stat fps";

// ---------- A镜面板（v0.3） ----------
@interface LDPanelHelper : NSObject
+ (LDPanelHelper *)shared;
- (void)pan:(UIPanGestureRecognizer *)gr;
// 面板动作（target-action，声明避免编译告警）
- (void)tabTap:(UIButton *)b;
- (void)histTap:(UIButton *)b;
- (void)aimSwitch:(UISwitch *)sw;
- (void)qualityTap:(UIButton *)b;
- (void)btnTap:(UIButton *)b;
- (void)joinServerTap:(UIButton *)b;
- (void)delServerTap:(UIButton *)b;
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

static UIView            *g_panel = nil;
static UILabel           *g_label = nil;
static dispatch_source_t g_timer = nil;

static void updateAimPanel(void) {
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
        g_label.text = [NSString stringWithFormat:
            @"A镜 | %@\n等级 Lv.%d\n\n生命 %d / %d\n眩晕 %d / %d\n耐力 %.1f\n氧气 %.1f\n食物 %.1f\n负重 %.1f\n近战 %.0f%%\n速度 %.0f%%",
            name, blv + elv,
            (int)hp, (int)mhp, (int)tp, (int)mtp,
            stamina, oxygen, food, weight, melee * 100.0f, speed * 100.0f];
    } @catch (NSException *e) {
        NSLog(@"[LD] updateAim exception: %@", e);
    }
}

static void setAimVisible(BOOL on) {
    if (on && !g_panel) {
        @try {
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
            if (!win) return;
            CGFloat W = win.bounds.size.width;
            g_panel = [[UIView alloc] initWithFrame:CGRectMake(W - 255, 90, 245, 300)];
            g_panel.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.72];
            g_panel.layer.cornerRadius = 12;
            g_panel.layer.borderWidth = 1;
            g_panel.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.35].CGColor;
            g_panel.userInteractionEnabled = YES;
            g_label = [[UILabel alloc] initWithFrame:CGRectMake(10, 10, 225, 280)];
            g_label.numberOfLines = 0;
            g_label.font = [UIFont systemFontOfSize:13];
            g_label.textColor = [UIColor whiteColor];
            g_label.text = @"A镜：未找到恐龙（进游戏后自动检测）";
            [g_panel addSubview:g_label];
            UIPanGestureRecognizer *drag = [[UIPanGestureRecognizer alloc] initWithTarget:[LDPanelHelper shared] action:@selector(pan:)];
            [g_panel addGestureRecognizer:drag];
            [win addSubview:g_panel];
            [win bringSubviewToFront:g_panel];
            g_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
            dispatch_source_set_timer(g_timer, dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), 0.5 * NSEC_PER_SEC, 0.05 * NSEC_PER_SEC);
            dispatch_source_set_event_handler(g_timer, ^{ updateAimPanel(); });
            dispatch_resume(g_timer);
        } @catch (NSException *e) {
            NSLog(@"[LD] setAimVisible on exception: %@", e);
        }
    } else if (!on && g_panel) {
        if (g_timer) { dispatch_source_cancel(g_timer); g_timer = nil; }
        [g_panel removeFromSuperview];
        g_panel = nil;
        g_label = nil;
    }
}

// ---------- 主面板 UI ----------
static UIView    *g_mainPanel = nil;
static UITextField *g_linkField = nil;
static UITextView *g_logView = nil;
static UITextField *g_codeField = nil;
static UIView    *g_tabJoin = nil;
static UIView    *g_tabQuality = nil;
static UISwitch  *g_aimSwitch = nil;
static UILabel   *g_fovLabel = nil;
static float g_fovValue = 90.0f;

static void logLine(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[LD] %@", msg);
    if (g_logView) {
        NSString *cur = g_logView.text ?: @"";
        g_logView.text = [cur stringByAppendingFormat:@"\n%@", msg];
        [g_logView scrollRangeToVisible:NSMakeRange(g_logView.text.length, 0)];
    }
}

static void showTab(int idx) {
    g_tabJoin.hidden = (idx != 0);
    g_tabQuality.hidden = (idx != 1);
}

// 服务器列表 UI（NSUserDefaults 数组：{name, remark, link}）
static UIView *g_srvListContainer = nil;

static void refreshServerListUI(void) {
    for (UIView *v in g_srvListContainer.subviews) [v removeFromSuperview];
    NSArray *list = loadServers();
    if (!list.count) {
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(8, 8, g_srvListContainer.bounds.size.width - 16, 20)];
        l.text = @"暂无保存的服务器";
        l.font = [UIFont systemFontOfSize:12];
        l.textColor = [UIColor colorWithWhite:1 alpha:0.5];
        [g_srvListContainer addSubview:l];
        return;
    }
    CGFloat y = 8;
    for (NSDictionary *d in list) {
        NSString *name = d[@"name"] ?: @"";
        NSString *remark = d[@"remark"] ?: @"";
        NSString *link = d[@"link"] ?: @"";
        NSString *label = name.length ? name : link;
        if (remark.length) label = [label stringByAppendingFormat:@"  [%@]", remark];
        CGFloat w = g_srvListContainer.bounds.size.width - 16;
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        b.frame = CGRectMake(8, y, w - 76, 30);
        b.backgroundColor = [UIColor colorWithWhite:1 alpha:0.12];
        b.layer.cornerRadius = 6;
        [b setTitle:label forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont systemFontOfSize:12];
        b.titleLabel.lineBreakMode = NSLineBreakByTruncatingTail;
        [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        b.tag = (NSInteger)[list indexOfObject:d];
        [b addTarget:[LDPanelHelper shared] action:@selector(joinServerTap:) forControlEvents:UIControlEventTouchUpInside];
        [g_srvListContainer addSubview:b];
        UIButton *del = [UIButton buttonWithType:UIButtonTypeSystem];
        del.frame = CGRectMake(w - 60, y, 52, 30);
        [del setTitle:@"删除" forState:UIControlStateNormal];
        del.titleLabel.font = [UIFont systemFontOfSize:12];
        del.tag = (NSInteger)[list indexOfObject:d];
        [del addTarget:[LDPanelHelper shared] action:@selector(delServerTap:) forControlEvents:UIControlEventTouchUpInside];
        [g_srvListContainer addSubview:del];
        y += 36;
    }
    g_srvListContainer.contentSize = CGSizeMake(g_srvListContainer.bounds.size.width, y + 8);
}

static void doJoinLink(NSString *link) {
    if (!link.length) { logLine(@"加入失败: 链接为空"); return; }
    NSString *host = nil; int port = 0;
    if (parseAddress(link, &host, &port)) {
        addHistory(link);
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "JoinServer:%s:%d", host.UTF8String, port);
        engineExec(cmd);
        logLine(@"加入服务器 %@:%d", host, port);
    } else {
        logLine(@"加入失败: 地址解析失败（支持 IP:端口 或加密链接）");
    }
}

// 目标-动作扩展：服务器加入/删除
@implementation LDPanelHelper (ServerActions)
- (void)joinServerTap:(UIButton *)b {
    NSArray *list = loadServers();
    NSInteger idx = b.tag;
    if (idx >= 0 && idx < (NSInteger)list.count) {
        NSDictionary *d = list[idx];
        NSString *link = d[@"link"] ?: @"";
        g_linkField.text = link;
        doJoinLink(link);
    }
}
- (void)delServerTap:(UIButton *)b {
    NSMutableArray *list = loadServers();
    NSInteger idx = b.tag;
    if (idx >= 0 && idx < (NSInteger)list.count) {
        [list removeObjectAtIndex:(NSUInteger)idx];
        saveServers(list);
        refreshServerListUI();
    }
}
@end

static void addServerPrompt(void) {
    @try {
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
        UIViewController *vc = win.rootViewController;
        if (!vc) return;
        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"添加服务器"
            message:@"名称 / 备注 / 链接（IP:端口 或加密链接）" preferredStyle:UIAlertControllerStyleAlert];
        [a addTextFieldWithConfigurationHandler:^(UITextField *tf){ tf.placeholder = @"服务器名称"; }];
        [a addTextFieldWithConfigurationHandler:^(UITextField *tf){ tf.placeholder = @"备注（可选）"; }];
        [a addTextFieldWithConfigurationHandler:^(UITextField *tf){ tf.placeholder = @"链接"; }];
        [a addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *act){
            UITextField *tfName = a.textFields[0];
            UITextField *tfLink = a.textFields[2];
            if (tfLink.text.length) {
                NSMutableArray *list = loadServers();
                [list addObject:@{@"name": tfName.text ?: @"", @"remark": a.textFields[1].text ?: @"", @"link": tfLink.text}];
                saveServers(list);
                refreshServerListUI();
            }
        }]];
        [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:a animated:YES completion:nil];
    } @catch (NSException *e) {
        NSLog(@"[LD] addServerPrompt exception: %@", e);
    }
}

static void sendCode(NSString *code) {
    if (!code.length) { logLine(@"发送失败: 代码为空"); return; }
    engineExec(code.UTF8String);
    logLine(@"已发送: %@", code);
}

static void buildMainPanel(void) {
    @try {
        if (g_mainPanel) return;
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
        if (!win) { NSLog(@"[LD] buildMainPanel: no window"); return; }
        CGFloat W = win.bounds.size.width;
        CGFloat H = win.bounds.size.height;
        CGFloat pw = MIN(W - 16, 380);
        CGFloat ph = MIN(H - 60, 560);

        g_mainPanel = [[UIView alloc] initWithFrame:CGRectMake((W - pw) / 2, (H - ph) / 2, pw, ph)];
        g_mainPanel.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.94];
        g_mainPanel.layer.cornerRadius = 14;
        g_mainPanel.layer.borderWidth = 1;
        g_mainPanel.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.3].CGColor;
        g_mainPanel.userInteractionEnabled = YES;

        // 拖动条
        UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, pw, 30)];
        bar.backgroundColor = [UIColor clearColor];
        UIPanGestureRecognizer *drag = [[UIPanGestureRecognizer alloc] initWithTarget:[LDPanelHelper shared] action:@selector(pan:)];
        [bar addGestureRecognizer:drag];
        [g_mainPanel addSubview:bar];

        // 标题
        UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(0, 4, pw, 22)];
        title.text = @"LD私服菜单 v0.4a";
        title.textColor = [UIColor whiteColor];
        title.font = [UIFont boldSystemFontOfSize:15];
        title.textAlignment = NSTextAlignmentCenter;
        [g_mainPanel addSubview:title];

        // Tab 切换
        UIButton *tab0 = [UIButton buttonWithType:UIButtonTypeSystem];
        tab0.frame = CGRectMake(12, 34, (pw - 24) / 2, 34);
        [tab0 setTitle:@"进服主页" forState:UIControlStateNormal];
        tab0.titleLabel.font = [UIFont boldSystemFontOfSize:14];
        [tab0 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        tab0.backgroundColor = [UIColor colorWithRed:0.2 green:0.5 blue:0.9 alpha:1];
        tab0.layer.cornerRadius = 8;
        tab0.tag = 0;
        [tab0 addTarget:[LDPanelHelper shared] action:@selector(tabTap:) forControlEvents:UIControlEventTouchUpInside];
        [g_mainPanel addSubview:tab0];
        UIButton *tab1 = [UIButton buttonWithType:UIButtonTypeSystem];
        tab1.frame = CGRectMake(12 + (pw - 24) / 2, 34, (pw - 24) / 2, 34);
        [tab1 setTitle:@"A镜画质" forState:UIControlStateNormal];
        tab1.titleLabel.font = [UIFont boldSystemFontOfSize:14];
        [tab1 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        tab1.backgroundColor = [UIColor colorWithWhite:1 alpha:0.15];
        tab1.layer.cornerRadius = 8;
        tab1.tag = 1;
        [tab1 addTarget:[LDPanelHelper shared] action:@selector(tabTap:) forControlEvents:UIControlEventTouchUpInside];
        [g_mainPanel addSubview:tab1];

        CGFloat y0 = 78;
        // ===== Tab0 进服主页 =====
        g_tabJoin = [[UIView alloc] initWithFrame:CGRectMake(0, y0, pw, ph - y0 - 8)];
        {
            g_linkField = [[UITextField alloc] initWithFrame:CGRectMake(12, 8, pw - 24, 38)];
            g_linkField.placeholder = @"输入链接（IP:端口 或加密链接）";
            g_linkField.textColor = [UIColor whiteColor];
            g_linkField.backgroundColor = [UIColor colorWithWhite:1 alpha:0.1];
            g_linkField.layer.cornerRadius = 8;
            g_linkField.font = [UIFont systemFontOfSize:13];
            g_linkField.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 8, 8)];
            g_linkField.leftViewMode = UITextFieldViewModeAlways;
            g_linkField.autocorrectionType = UITextAutocorrectionTypeNo;
            g_linkField.autocapitalizationType = UITextAutocapitalizationTypeNone;
            [g_tabJoin addSubview:g_linkField];

            CGFloat btnW = (pw - 24 - 16) / 3;
            UIButton *bPaste = [UIButton buttonWithType:UIButtonTypeSystem];
            bPaste.frame = CGRectMake(12, 54, btnW, 34);
            [bPaste setTitle:@"粘贴" forState:UIControlStateNormal];
            bPaste.tag = 100;
            [bPaste addTarget:[LDPanelHelper shared] action:@selector(btnTap:) forControlEvents:UIControlEventTouchUpInside];
            [g_tabJoin addSubview:bPaste];
            UIButton *bClear = [UIButton buttonWithType:UIButtonTypeSystem];
            bClear.frame = CGRectMake(12 + btnW + 8, 54, btnW, 34);
            [bClear setTitle:@"清除" forState:UIControlStateNormal];
            bClear.tag = 101;
            [bClear addTarget:[LDPanelHelper shared] action:@selector(btnTap:) forControlEvents:UIControlEventTouchUpInside];
            [g_tabJoin addSubview:bClear];
            UIButton *bJoin = [UIButton buttonWithType:UIButtonTypeSystem];
            bJoin.frame = CGRectMake(12 + (btnW + 8) * 2, 54, btnW, 34);
            [bJoin setTitle:@"加入" forState:UIControlStateNormal];
            bJoin.titleLabel.font = [UIFont boldSystemFontOfSize:14];
            bJoin.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:0.3 alpha:1];
            bJoin.layer.cornerRadius = 8;
            bJoin.tag = 102;
            [bJoin addTarget:[LDPanelHelper shared] action:@selector(btnTap:) forControlEvents:UIControlEventTouchUpInside];
            [g_tabJoin addSubview:bJoin];

            // 历史记录（最近 5 条，点击填入）
            UILabel *histTitle = [[UILabel alloc] initWithFrame:CGRectMake(12, 96, pw - 24, 18)];
            histTitle.text = @"历史记录（点击填入）：";
            histTitle.font = [UIFont systemFontOfSize:12];
            histTitle.textColor = [UIColor colorWithWhite:1 alpha:0.6];
            [g_tabJoin addSubview:histTitle];
            UIScrollView *hist = [[UIScrollView alloc] initWithFrame:CGRectMake(12, 116, pw - 24, 110)];
            hist.backgroundColor = [UIColor colorWithWhite:1 alpha:0.06];
            hist.layer.cornerRadius = 8;
            NSArray *h = loadHistory();
            CGFloat hy = 4;
            for (NSString *item in h) {
                if (hy > 100) break;
                UIButton *hb = [UIButton buttonWithType:UIButtonTypeSystem];
                hb.frame = CGRectMake(4, hy, hist.bounds.size.width - 8, 24);
                [hb setTitle:item forState:UIControlStateNormal];
                hb.titleLabel.font = [UIFont systemFontOfSize:11];
                hb.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
                hb.titleLabel.lineBreakMode = NSLineBreakByTruncatingMiddle;
                hb.tag = 200 + (NSInteger)[h indexOfObject:item];
                [hb addTarget:[LDPanelHelper shared] action:@selector(histTap:) forControlEvents:UIControlEventTouchUpInside];
                [hist addSubview:hb];
                hy += 26;
            }
            if (!h.count) {
                UILabel *el = [[UILabel alloc] initWithFrame:CGRectMake(4, 4, hist.bounds.size.width - 8, 20)];
                el.text = @"无历史记录";
                el.font = [UIFont systemFontOfSize:11];
                el.textColor = [UIColor colorWithWhite:1 alpha:0.4];
                [hist addSubview:el];
            }
            hist.contentSize = CGSizeMake(hist.bounds.size.width, hy + 4);
            [g_tabJoin addSubview:hist];

            // 已保存服务器
            UIButton *bAddSrv = [UIButton buttonWithType:UIButtonTypeSystem];
            bAddSrv.frame = CGRectMake(12, 232, pw - 24, 32);
            [bAddSrv setTitle:@"+ 添加服务器" forState:UIControlStateNormal];
            bAddSrv.tag = 103;
            bAddSrv.backgroundColor = [UIColor colorWithWhite:1 alpha:0.15];
            bAddSrv.layer.cornerRadius = 8;
            [bAddSrv addTarget:[LDPanelHelper shared] action:@selector(btnTap:) forControlEvents:UIControlEventTouchUpInside];
            [g_tabJoin addSubview:bAddSrv];

            g_srvListContainer = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 270, pw, g_tabJoin.bounds.size.height - 270)];
            g_srvListContainer.backgroundColor = [UIColor clearColor];
            [g_tabJoin addSubview:g_srvListContainer];
            refreshServerListUI();
        }
        [g_mainPanel addSubview:g_tabJoin];

        // ===== Tab1 A镜画质 =====
        g_tabQuality = [[UIView alloc] initWithFrame:CGRectMake(0, y0, pw, ph - y0 - 8)];
        {
            CGFloat qy = 8;
            // A镜开关
            UILabel *aimL = [[UILabel alloc] initWithFrame:CGRectMake(12, qy, 120, 30)];
            aimL.text = @"A镜开关";
            aimL.textColor = [UIColor whiteColor];
            aimL.font = [UIFont systemFontOfSize:14];
            [g_tabQuality addSubview:aimL];
            g_aimSwitch = [[UISwitch alloc] initWithFrame:CGRectMake(pw - 70, qy - 4, 60, 30)];
            g_aimSwitch.on = YES;
            [g_aimSwitch addTarget:[LDPanelHelper shared] action:@selector(aimSwitch:) forControlEvents:UIControlEventValueChanged];
            [g_tabQuality addSubview:g_aimSwitch];
            qy += 36;

            // FOV 广角
            UILabel *fovL = [[UILabel alloc] initWithFrame:CGRectMake(12, qy, 80, 30)];
            fovL.text = @"广角";
            fovL.textColor = [UIColor whiteColor];
            fovL.font = [UIFont systemFontOfSize:14];
            [g_tabQuality addSubview:fovL];
            UIButton *fovMinus = [UIButton buttonWithType:UIButtonTypeSystem];
            fovMinus.frame = CGRectMake(100, qy, 44, 30);
            [fovMinus setTitle:@"−" forState:UIControlStateNormal];
            fovMinus.tag = 110;
            [fovMinus addTarget:[LDPanelHelper shared] action:@selector(btnTap:) forControlEvents:UIControlEventTouchUpInside];
            [g_tabQuality addSubview:fovMinus];
            g_fovLabel = [[UILabel alloc] initWithFrame:CGRectMake(150, qy, 60, 30)];
            g_fovLabel.text = @"90";
            g_fovLabel.textColor = [UIColor whiteColor];
            g_fovLabel.font = [UIFont systemFontOfSize:14];
            g_fovLabel.textAlignment = NSTextAlignmentCenter;
            [g_tabQuality addSubview:g_fovLabel];
            UIButton *fovPlus = [UIButton buttonWithType:UIButtonTypeSystem];
            fovPlus.frame = CGRectMake(210, qy, 44, 30);
            [fovPlus setTitle:@"＋" forState:UIControlStateNormal];
            fovPlus.tag = 111;
            [fovPlus addTarget:[LDPanelHelper shared] action:@selector(btnTap:) forControlEvents:UIControlEventTouchUpInside];
            [g_tabQuality addSubview:fovPlus];
            qy += 38;

            // 画质预设（2x2）
            CGFloat qbw = (pw - 12 - 8 - 24) / 2;
            NSArray *presets = @[@"4K画质", @"高清画质", @"战斗画质", @"恢复画质"];
            for (int i = 0; i < 4; i++) {
                UIButton *qb = [UIButton buttonWithType:UIButtonTypeSystem];
                int row = i / 2, col = i % 2;
                qb.frame = CGRectMake(12 + col * (qbw + 8), qy + row * 38, qbw, 32);
                [qb setTitle:presets[i] forState:UIControlStateNormal];
                qb.titleLabel.font = [UIFont systemFontOfSize:13];
                qb.backgroundColor = [UIColor colorWithWhite:1 alpha:0.15];
                qb.layer.cornerRadius = 8;
                qb.tag = 120 + i;
                [qb addTarget:[LDPanelHelper shared] action:@selector(qualityTap:) forControlEvents:UIControlEventTouchUpInside];
                [g_tabQuality addSubview:qb];
            }
            qy += 82;

            // 自定义代码
            UILabel *codeL = [[UILabel alloc] initWithFrame:CGRectMake(12, qy, pw - 24, 18)];
            codeL.text = @"自定义画质/代码：";
            codeL.font = [UIFont systemFontOfSize:12];
            codeL.textColor = [UIColor colorWithWhite:1 alpha:0.6];
            [g_tabQuality addSubview:codeL];
            qy += 22;
            g_codeField = [[UITextField alloc] initWithFrame:CGRectMake(12, qy, pw - 24, 36)];
            g_codeField.placeholder = @"输入代码，如 r.volumetricfog 0";
            g_codeField.textColor = [UIColor whiteColor];
            g_codeField.backgroundColor = [UIColor colorWithWhite:1 alpha:0.1];
            g_codeField.layer.cornerRadius = 8;
            g_codeField.font = [UIFont systemFontOfSize:13];
            g_codeField.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 8, 8)];
            g_codeField.leftViewMode = UITextFieldViewModeAlways;
            g_codeField.autocorrectionType = UITextAutocorrectionTypeNo;
            g_codeField.autocapitalizationType = UITextAutocapitalizationTypeNone;
            [g_tabQuality addSubview:g_codeField];
            qy += 44;

            CGFloat cbtnW = (pw - 24 - 16) / 3;
            UIButton *bCodePaste = [UIButton buttonWithType:UIButtonTypeSystem];
            bCodePaste.frame = CGRectMake(12, qy, cbtnW, 34);
            [bCodePaste setTitle:@"粘贴" forState:UIControlStateNormal];
            bCodePaste.tag = 130;
            [bCodePaste addTarget:[LDPanelHelper shared] action:@selector(btnTap:) forControlEvents:UIControlEventTouchUpInside];
            [g_tabQuality addSubview:bCodePaste];
            UIButton *bCodeClear = [UIButton buttonWithType:UIButtonTypeSystem];
            bCodeClear.frame = CGRectMake(12 + cbtnW + 8, qy, cbtnW, 34);
            [bCodeClear setTitle:@"清除" forState:UIControlStateNormal];
            bCodeClear.tag = 131;
            [bCodeClear addTarget:[LDPanelHelper shared] action:@selector(btnTap:) forControlEvents:UIControlEventTouchUpInside];
            [g_tabQuality addSubview:bCodeClear];
            UIButton *bCodeSend = [UIButton buttonWithType:UIButtonTypeSystem];
            bCodeSend.frame = CGRectMake(12 + (cbtnW + 8) * 2, qy, cbtnW, 34);
            [bCodeSend setTitle:@"发送" forState:UIControlStateNormal];
            bCodeSend.titleLabel.font = [UIFont boldSystemFontOfSize:14];
            bCodeSend.backgroundColor = [UIColor colorWithRed:0.2 green:0.5 blue:0.9 alpha:1];
            bCodeSend.layer.cornerRadius = 8;
            bCodeSend.tag = 132;
            [bCodeSend addTarget:[LDPanelHelper shared] action:@selector(btnTap:) forControlEvents:UIControlEventTouchUpInside];
            [g_tabQuality addSubview:bCodeSend];
            qy += 42;

            // 礼包
            UILabel *giftL = [[UILabel alloc] initWithFrame:CGRectMake(12, qy, pw - 24, 18)];
            giftL.text = @"礼包：";
            giftL.font = [UIFont systemFontOfSize:12];
            giftL.textColor = [UIColor colorWithWhite:1 alpha:0.6];
            [g_tabQuality addSubview:giftL];
            qy += 22;
            CGFloat gbtnW = (pw - 24 - 8) / 2;
            UIButton *bDaily = [UIButton buttonWithType:UIButtonTypeSystem];
            bDaily.frame = CGRectMake(12, qy, gbtnW, 34);
            [bDaily setTitle:@"领取每日礼包" forState:UIControlStateNormal];
            bDaily.titleLabel.font = [UIFont systemFontOfSize:13];
            bDaily.backgroundColor = [UIColor colorWithRed:0.8 green:0.5 blue:0.2 alpha:1];
            bDaily.layer.cornerRadius = 8;
            bDaily.tag = 140;
            [bDaily addTarget:[LDPanelHelper shared] action:@selector(btnTap:) forControlEvents:UIControlEventTouchUpInside];
            [g_tabQuality addSubview:bDaily];
            UIButton *bMonthly = [UIButton buttonWithType:UIButtonTypeSystem];
            bMonthly.frame = CGRectMake(12 + gbtnW + 8, qy, gbtnW, 34);
            [bMonthly setTitle:@"领取每月礼包" forState:UIControlStateNormal];
            bMonthly.titleLabel.font = [UIFont systemFontOfSize:13];
            bMonthly.backgroundColor = [UIColor colorWithRed:0.8 green:0.5 blue:0.2 alpha:1];
            bMonthly.layer.cornerRadius = 8;
            bMonthly.tag = 141;
            [bMonthly addTarget:[LDPanelHelper shared] action:@selector(btnTap:) forControlEvents:UIControlEventTouchUpInside];
            [g_tabQuality addSubview:bMonthly];
            qy += 42;

            // 日志
            g_logView = [[UITextView alloc] initWithFrame:CGRectMake(12, qy, pw - 24, g_tabQuality.bounds.size.height - qy - 12)];
            g_logView.backgroundColor = [UIColor colorWithWhite:0 alpha:0.4];
            g_logView.textColor = [UIColor colorWithRed:0.5 green:1 blue:0.5 alpha:1];
            g_logView.font = [UIFont systemFontOfSize:10];
            g_logView.editable = NO;
            g_logView.layer.cornerRadius = 8;
            [g_tabQuality addSubview:g_logView];
            logLine(@"LD v0.4a 就绪");
        }
        [g_mainPanel addSubview:g_tabQuality];

        // 关闭按钮
        UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
        close.frame = CGRectMake(pw - 36, 2, 30, 26);
        [close setTitle:@"✕" forState:UIControlStateNormal];
        [close setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        close.tag = 199;
        [close addTarget:[LDPanelHelper shared] action:@selector(btnTap:) forControlEvents:UIControlEventTouchUpInside];
        [g_mainPanel addSubview:close];

        [win addSubview:g_mainPanel];
        [win bringSubviewToFront:g_mainPanel];
        showTab(0);
        NSLog(@"[LD] main panel built");
    } @catch (NSException *e) {
        NSLog(@"[LD] buildMainPanel exception: %@", e);
    }
}

// ---------- 面板按钮动作 ----------
@implementation LDPanelHelper (PanelActions)
- (void)tabTap:(UIButton *)b {
    showTab((int)b.tag);
}
- (void)histTap:(UIButton *)b {
    NSArray *h = loadHistory();
    NSInteger idx = b.tag - 200;
    if (idx >= 0 && idx < (NSInteger)h.count) g_linkField.text = h[idx];
}
- (void)aimSwitch:(UISwitch *)sw {
    setAimVisible(sw.on);
}
- (void)qualityTap:(UIButton *)b {
    const char *cmd = NULL;
    switch (b.tag) {
        case 120: cmd = g_quality4k; break;
        case 121: cmd = g_qualityHD; break;
        case 122: cmd = g_qualityBattle; break;
        case 123: cmd = g_qualityReset; break;
    }
    if (cmd) { engineExec(cmd); logLine(@"画质已下发: %@", b.titleLabel.text ?: @""); }
}
- (void)btnTap:(UIButton *)b {
    switch (b.tag) {
        case 100: { // 粘贴链接
            NSString *clip = [UIPasteboard generalPasteboard].string;
            if (clip.length) { g_linkField.text = clip; addHistory(clip); }
            break;
        }
        case 101: g_linkField.text = @""; break;
        case 102: doJoinLink(g_linkField.text); break;
        case 103: addServerPrompt(); break;
        case 110: { // FOV -
            g_fovValue -= 5.0f; if (g_fovValue < 30.0f) g_fovValue = 30.0f;
            g_fovLabel.text = [NSString stringWithFormat:@"%.0f", g_fovValue];
            char buf[64]; snprintf(buf, sizeof(buf), "FOV %.0f", g_fovValue);
            engineExec(buf); logLine(@"FOV %.0f", g_fovValue);
            break;
        }
        case 111: { // FOV +
            g_fovValue += 5.0f; if (g_fovValue > 200.0f) g_fovValue = 200.0f;
            g_fovLabel.text = [NSString stringWithFormat:@"%.0f", g_fovValue];
            char buf[64]; snprintf(buf, sizeof(buf), "FOV %.0f", g_fovValue);
            engineExec(buf); logLine(@"FOV %.0f", g_fovValue);
            break;
        }
        case 130: { // 代码粘贴
            NSString *clip = [UIPasteboard generalPasteboard].string;
            if (clip.length) g_codeField.text = clip;
            break;
        }
        case 131: g_codeField.text = @""; break;
        case 132: sendCode(g_codeField.text); break;
        case 140: engineExec("JDARK_GIFT|DAILY"); logLine(@"已领取每日礼包"); break;
        case 141: engineExec("JDARK_GIFT|MONTHLY"); logLine(@"已领取每月礼包"); break;
        case 199: { // 关闭
            if (g_mainPanel) { [g_mainPanel removeFromSuperview]; g_mainPanel = nil; }
            break;
        }
    }
}
@end

// ---------- 注入入口 ----------
__attribute__((constructor))
static void ld_init() {
    NSLog(@"[LD-iOS] 注入成功 v0.4a 进服+画质版");
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
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

            UIAlertController *a = [UIAlertController alertControllerWithTitle:@"LD私服菜单 v0.4a"
                message:@"注入成功（主面板 2 秒后启动，A镜默认开启）"
                preferredStyle:UIAlertControllerStyleAlert];
            [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
            [vc presentViewController:a animated:YES completion:nil];
            NSLog(@"[LD] alert shown, scheduling panel in 2s");

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                buildMainPanel();
                setAimVisible(YES);
                NSLog(@"[LD] panel started");
            });
        } @catch (NSException *e) {
            NSLog(@"[LD] ld_init exception: %@", e);
        }
    });
}
