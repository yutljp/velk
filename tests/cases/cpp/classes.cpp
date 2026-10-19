// C++ classes: virtual dispatch, constructors, templates, references, operators.
struct Shape {
    virtual ~Shape() {}
    virtual int area() const = 0;
};

struct Square : Shape {
    int side;
    explicit Square(int s) : side(s) {}
    int area() const override { return side * side; }
};

struct Rect : Shape {
    int w, h;
    Rect(int w_, int h_) : w(w_), h(h_) {}
    int area() const override { return w * h; }
};

int total_area(const Shape *const *shapes, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += shapes[i]->area();
    return total;
}

template <typename T>
T clamp(T value, T lo, T hi) { return value < lo ? lo : (value > hi ? hi : value); }

int clamp_int(int v) { return clamp<int>(v, 0, 255); }
long clamp_long(long v) { return clamp<long>(v, -1000, 1000); }

struct Vec2 {
    int x, y;
    Vec2 operator+(const Vec2 &o) const { return Vec2{x + o.x, y + o.y}; }
};

int dot_sum(const Vec2 &a, const Vec2 &b) {
    Vec2 s = a + b;
    return s.x * s.y;
}

void increment(int &value) { value += 1; }
