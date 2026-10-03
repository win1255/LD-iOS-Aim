#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// ============================================================
// LD-iOS 最小验证插件 v0.1
// 目的：验证 GitHub Actions 云编译链路 + 注入/签名流程
// 后续功能（A镜、商城、皮肤、mod挂载）在此文件体系内扩展
// ============================================================

__attribute__((constructor))
static void ld_init() {
    NSLog(@"[LD-iOS] 注入成功 v0.1 骨架版");
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *win = nil;
        if (@available(iOS 13.0, *)) {
            win = [UIApplication sharedApplication].connectedScenes
                    .allObjects.count ?
              ((UIWindowScene *)[UIApplication sharedApplication].connectedScenes.allObjects.firstObject).keyWindow : nil;
        }
        if (!win) win = [[UIApplication sharedApplication] keyWindow];
        if (!win) return;
        UIViewController *vc = win.rootViewController;
        if (!vc) return;
        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"LD-iOS"
                                                                   message:@"注入成功，云编译链路 OK"
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
        [vc presentViewController:a animated:YES completion:nil];
    });
}
