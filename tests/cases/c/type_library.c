#include <grp.h>
#include <stddef.h>
#include <wchar.h>

__attribute__((noinline)) unsigned int library_group(struct group *entry) {
    getgrgid_r(7, entry, NULL, 0, NULL);
    return entry->gr_gid;
}

__attribute__((noinline)) size_t library_wide_length(const wchar_t *text) {
    return wcslen(text);
}

__attribute__((noinline)) unsigned int library_group_at(struct group *entries, size_t index) {
    getgrgid_r(7, entries, NULL, 0, NULL);
    return entries[index].gr_gid;
}

int main(void) {
    return 0;
}
