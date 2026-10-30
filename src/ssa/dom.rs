//! Dominators and dominance frontiers over a function's blocks, by the
//! iterative algorithm on reverse postorder.

/// The immediate dominator of each block reachable from the entry, and
/// `None` for the entry and unreachable blocks.
pub(crate) struct Dominators {
    pub idom: Vec<Option<usize>>,
}

pub(super) fn predecessors(successors: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let mut predecessors = vec![Vec::new(); successors.len()];
    for (block, next) in successors.iter().enumerate() {
        for successor in next {
            predecessors[*successor].push(block);
        }
    }
    predecessors
}

pub(crate) fn dominators(successors: &[Vec<usize>]) -> Dominators {
    let count = successors.len();
    let mut order = Vec::with_capacity(count);
    if count == 0 {
        return Dominators { idom: Vec::new() };
    }
    // Postorder by an explicit stack, so deep graphs do not overflow.
    let mut visited = vec![false; count];
    let mut stack = vec![(0usize, 0usize)];
    visited[0] = true;
    while let Some((block, next)) = stack.last_mut() {
        if let Some(successor) = successors[*block].get(*next).copied() {
            *next += 1;
            if !visited[successor] {
                visited[successor] = true;
                stack.push((successor, 0));
            }
        } else {
            order.push(*block);
            stack.pop();
        }
    }
    order.reverse();
    let mut position = vec![usize::MAX; count];
    for (index, block) in order.iter().enumerate() {
        position[*block] = index;
    }
    let predecessors = predecessors(successors);
    let mut idom: Vec<Option<usize>> = vec![None; count];
    idom[0] = Some(0);
    let intersect = |idom: &[Option<usize>], mut a: usize, mut b: usize| {
        while a != b {
            while position[a] > position[b] {
                a = idom[a].expect("processed");
            }
            while position[b] > position[a] {
                b = idom[b].expect("processed");
            }
        }
        a
    };
    loop {
        let mut changed = false;
        let blocks_after_entry = order.iter().copied().skip(1);
        for block in blocks_after_entry {
            let mut new = None;
            for predecessor in &predecessors[block] {
                if idom[*predecessor].is_none() {
                    continue;
                }
                new = Some(match new {
                    None => *predecessor,
                    Some(current) => intersect(&idom, *predecessor, current),
                });
            }
            if new.is_some() && idom[block] != new {
                idom[block] = new;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    idom[0] = None;
    Dominators { idom }
}

/// The dominance frontier of each block: where its dominance ends.
pub(crate) fn frontiers(successors: &[Vec<usize>], dominators: &Dominators) -> Vec<Vec<usize>> {
    let count = successors.len();
    let predecessors = predecessors(successors);
    let reachable = |block: usize| block == 0 || dominators.idom[block].is_some();
    let mut frontier = vec![Vec::new(); count];
    for (block, from) in predecessors.iter().enumerate() {
        if !reachable(block) {
            continue;
        }
        let reaching: Vec<usize> = from
            .iter()
            .copied()
            .filter(|predecessor| reachable(*predecessor))
            .collect();
        // The call into the function enters the entry block too.
        if reaching.len() + usize::from(block == 0) < 2 {
            continue;
        }
        for predecessor in reaching {
            let mut runner = predecessor;
            while Some(runner) != dominators.idom[block] {
                if !frontier[runner].contains(&block) {
                    frontier[runner].push(block);
                }
                match dominators.idom[runner] {
                    Some(up) => runner = up,
                    None => break,
                }
            }
        }
    }
    frontier
}

#[cfg(test)]
mod tests {
    use super::{dominators, frontiers};

    #[test]
    fn a_diamond_joins_at_its_bottom() {
        // 0 -> 1, 2; 1 -> 3; 2 -> 3
        let successors = vec![vec![1, 2], vec![3], vec![3], vec![]];
        let dominators = dominators(&successors);
        assert_eq!(dominators.idom, vec![None, Some(0), Some(0), Some(0)]);
        let frontier = frontiers(&successors, &dominators);
        assert_eq!(frontier[1], vec![3]);
        assert_eq!(frontier[2], vec![3]);
        assert!(frontier[0].is_empty());
    }

    #[test]
    fn a_loop_body_has_its_header_in_its_frontier() {
        // 0 -> 1; 1 -> 2, 3; 2 -> 1
        let successors = vec![vec![1], vec![2, 3], vec![1], vec![]];
        let dominators = dominators(&successors);
        assert_eq!(dominators.idom, vec![None, Some(0), Some(1), Some(1)]);
        let frontier = frontiers(&successors, &dominators);
        assert_eq!(frontier[2], vec![1]);
        assert!(frontier[1].contains(&1));
    }
}
