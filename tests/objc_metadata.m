@protocol Value
- (long)add:(long)x with:(long)y;
@end
__attribute__((objc_root_class))
@interface Counter <Value> { long _value; }
@property long value;
+ (long)answer;
@end
@implementation Counter
@synthesize value = _value;
- (long)add:(long)x with:(long)y { return x + y; }
+ (long)answer { return 42; }
@end
@interface Counter (Extra)
- (long)twice:(long)x;
@end
@implementation Counter (Extra)
- (long)twice:(long)x { return x * 2; }
@end
long send_value(Counter *object, long x, long y) { return [object add:x with:y]; }
long use_block(long x) { long (^block)(long) = ^(long y) { return y + 3; }; return block(x); }
int main(void) { return 0; }
