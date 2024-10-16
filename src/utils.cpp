#include "../include/utils.hpp"

#include <sys/mman.h>

namespace Goblin {

inline void IDs::free_id(const id_t id) { m_free_ids.push(id); }

id_t IDs::allocate_id(void) {
    if (m_free_ids.empty()) {
        m_biggest_allocated++;
        return m_biggest_allocated;
    } else { // just repurpose a free used one
        id_t foo = m_free_ids.front();
        m_free_ids.pop();
        return foo;
    }
}

} // namespace Goblin
