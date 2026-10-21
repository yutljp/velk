// C++ virtual calls: through the table a constructor the caller cannot see
// stores, and through an object of unknown type. Linked without a runtime,
// so it brings its own allocator and pure virtual handler.
extern "C" void __cxa_pure_virtual() { __builtin_trap(); }

static char arena[4096];
static unsigned long used;
void *operator new(unsigned long size) {
  void *p = arena + used;
  used += (size + 15) & ~15UL;
  return p;
}
void operator delete(void *) noexcept {}
void operator delete(void *, unsigned long) noexcept {}

struct Shape {
  virtual ~Shape();
  virtual int area() const = 0;
  virtual int scaled(int k) const;
};

struct Square : Shape {
  int side;
  explicit Square(int s);
  int area() const override;
};

struct Rect : Shape {
  int w, h;
  Rect(int w_, int h_);
  int area() const override;
  int scaled(int k) const override;
};

Shape::~Shape() {}
int Shape::scaled(int k) const { return area() * k; }

__attribute__((noinline)) Square::Square(int s) : side(s) {}
int Square::area() const { return side * side; }

__attribute__((noinline)) Rect::Rect(int w_, int h_) : w(w_), h(h_) {}
int Rect::area() const { return w * h; }
int Rect::scaled(int k) const { return w * h * k + 1; }

int square_area(int s) {
  Shape *shape = new Square(s);
  int a = shape->area();
  delete shape;
  return a;
}

int rect_scaled(int w, int h, int k) {
  Shape *shape = new Rect(w, h);
  return shape->scaled(k);
}

int any_area(const Shape *shape) { return shape->area(); }

int any_scaled(const Shape *shape, int k) { return shape->scaled(k); }
