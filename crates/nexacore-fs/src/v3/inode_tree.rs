//! Copy-on-write inode tree — a persistent ordered map from inode number to the
//! block that holds the inode (WS3-01.3, NCIP-027 §S2).
//!
//! The inode tree is the CoW metadata object that indexes every inode. Because
//! v3 never overwrites live metadata (a commit publishes a new generation via
//! the dual superblock, WS3-01.2), the tree must be **persistent**: mutating it
//! yields a *new* root while every retained root — a snapshot's, or the
//! previous generation's — keeps observing exactly what it did before. This is
//! the copy-on-write property that makes O(1) snapshots (WS3-01.10) and the
//! commit barrier (WS3-03.4) sound.
//!
//! It is realised here as a **persistent AVL tree** with path copying: an
//! insert or remove rebuilds only the nodes on the root-to-leaf path (`O(log n)`
//! new nodes) and structurally shares every untouched subtree with the prior
//! tree via [`Rc`]. Balancing keeps lookups `O(log n)`. The structure is pure
//! `core`/`alloc` logic; serialising a node to a multi-block object is a
//! follow-up (the [`super::superblock::SuperblockV3`] carries the committed
//! root, and [`super::extent::AllocMap::alloc_run`] backs multi-block nodes).

use alloc::{rc::Rc, vec::Vec};
use core::cmp::{Ordering, max};

/// An immutable AVL node. Nodes are never mutated in place; a change builds a
/// fresh node and shares the untouched children.
#[derive(Debug, PartialEq, Eq)]
struct Node {
    key: u64,
    val: u64,
    height: i32,
    left: Option<Rc<Node>>,
    right: Option<Rc<Node>>,
}

/// The height of a subtree (`0` for an empty one).
fn height(node: Option<&Rc<Node>>) -> i32 {
    node.map_or(0, |n| n.height)
}

/// Build a node, computing its height from its children.
fn node(key: u64, val: u64, left: Option<Rc<Node>>, right: Option<Rc<Node>>) -> Rc<Node> {
    let height = 1 + max(height(left.as_ref()), height(right.as_ref()));
    Rc::new(Node {
        key,
        val,
        height,
        left,
        right,
    })
}

/// Right rotation with `pivot` as the current root's left child.
fn rotate_right(key: u64, val: u64, pivot: &Rc<Node>, right: Option<Rc<Node>>) -> Rc<Node> {
    let new_right = node(key, val, pivot.right.clone(), right);
    node(pivot.key, pivot.val, pivot.left.clone(), Some(new_right))
}

/// Left rotation with `pivot` as the current root's right child.
fn rotate_left(key: u64, val: u64, left: Option<Rc<Node>>, pivot: &Rc<Node>) -> Rc<Node> {
    let new_left = node(key, val, left, pivot.left.clone());
    node(pivot.key, pivot.val, Some(new_left), pivot.right.clone())
}

/// Build a node from `(key, val, left, right)`, rebalancing if the two subtrees
/// differ in height by more than one (the standard AVL LL/LR/RL/RR cases).
fn rebalance(key: u64, val: u64, left: Option<Rc<Node>>, right: Option<Rc<Node>>) -> Rc<Node> {
    let bf = height(left.as_ref()) - height(right.as_ref());
    if bf > 1 {
        if let Some(l) = left.clone() {
            if height(l.left.as_ref()) >= height(l.right.as_ref()) {
                // Left-Left
                return rotate_right(key, val, &l, right);
            } else if let Some(lr) = l.right.clone() {
                // Left-Right: rotate the left child left, then rotate right.
                let new_left = rotate_left(l.key, l.val, l.left.clone(), &lr);
                return rotate_right(key, val, &new_left, right);
            }
        }
    } else if bf < -1 {
        if let Some(r) = right.clone() {
            if height(r.right.as_ref()) >= height(r.left.as_ref()) {
                // Right-Right
                return rotate_left(key, val, left, &r);
            } else if let Some(rl) = r.left.clone() {
                // Right-Left: rotate the right child right, then rotate left.
                let new_right = rotate_right(r.key, r.val, &rl, r.right.clone());
                return rotate_left(key, val, left, &new_right);
            }
        }
    }
    node(key, val, left, right)
}

/// Insert `(key, val)` into `subtree`, returning the new subtree and whether a
/// new key was added (as opposed to an existing value being replaced).
fn insert(subtree: Option<&Rc<Node>>, key: u64, val: u64) -> (Rc<Node>, bool) {
    subtree.map_or_else(
        || (node(key, val, None, None), true),
        |n| match key.cmp(&n.key) {
            Ordering::Less => {
                let (new_left, added) = insert(n.left.as_ref(), key, val);
                (
                    rebalance(n.key, n.val, Some(new_left), n.right.clone()),
                    added,
                )
            }
            Ordering::Greater => {
                let (new_right, added) = insert(n.right.as_ref(), key, val);
                (
                    rebalance(n.key, n.val, n.left.clone(), Some(new_right)),
                    added,
                )
            }
            // Replace the value; the shape (and heights) are unchanged.
            Ordering::Equal => (node(n.key, val, n.left.clone(), n.right.clone()), false),
        },
    )
}

/// The smallest `(key, val)` in the subtree rooted at `n` (its leftmost node).
fn min_entry(n: &Rc<Node>) -> (u64, u64) {
    let mut cur = n;
    while let Some(l) = cur.left.as_ref() {
        cur = l;
    }
    (cur.key, cur.val)
}

/// Remove `key` from `subtree`, returning the new subtree and whether a key was
/// actually removed.
fn remove(subtree: Option<&Rc<Node>>, key: u64) -> (Option<Rc<Node>>, bool) {
    subtree.map_or((None, false), |n| match key.cmp(&n.key) {
        Ordering::Less => {
            let (new_left, removed) = remove(n.left.as_ref(), key);
            (
                Some(rebalance(n.key, n.val, new_left, n.right.clone())),
                removed,
            )
        }
        Ordering::Greater => {
            let (new_right, removed) = remove(n.right.as_ref(), key);
            (
                Some(rebalance(n.key, n.val, n.left.clone(), new_right)),
                removed,
            )
        }
        Ordering::Equal => match (&n.left, &n.right) {
            (None, None) => (None, true),
            (Some(l), None) => (Some(l.clone()), true),
            (None, Some(r)) => (Some(r.clone()), true),
            (Some(_), Some(right)) => {
                // Replace with the in-order successor (min of the right
                // subtree, which exists here) and delete it from the right.
                let (sk, sv) = min_entry(right);
                let (new_right, _) = remove(n.right.as_ref(), sk);
                (Some(rebalance(sk, sv, n.left.clone(), new_right)), true)
            }
        },
    })
}

/// Collect `(key, val)` pairs in ascending key order into `out`.
fn collect(subtree: Option<&Rc<Node>>, out: &mut Vec<(u64, u64)>) {
    if let Some(n) = subtree {
        collect(n.left.as_ref(), out);
        out.push((n.key, n.val));
        collect(n.right.as_ref(), out);
    }
}

/// A copy-on-write inode tree: a persistent map from inode number to the block
/// that stores the inode.
///
/// Every mutator ([`InodeTree::with_inserted`], [`InodeTree::with_removed`])
/// returns a **new** tree and leaves `self` — and any snapshot holding an older
/// tree — untouched; unchanged subtrees are shared, not copied. Cloning a tree
/// is `O(1)` (an [`Rc`] bump), which is what makes a snapshot cheap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InodeTree {
    root: Option<Rc<Node>>,
    len: usize,
}

impl InodeTree {
    /// The empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of inodes in the tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the tree holds no inodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The height of the tree (`0` when empty). Bounded by `1.44·log₂(n)` — the
    /// AVL balance invariant — so lookups are `O(log n)`.
    #[must_use]
    pub fn height(&self) -> u32 {
        u32::try_from(height(self.root.as_ref())).unwrap_or(0)
    }

    /// The block storing `inode`, or `None` if the inode is not present.
    #[must_use]
    pub fn get(&self, inode: u64) -> Option<u64> {
        let mut cur = self.root.as_ref();
        while let Some(n) = cur {
            match inode.cmp(&n.key) {
                Ordering::Less => cur = n.left.as_ref(),
                Ordering::Greater => cur = n.right.as_ref(),
                Ordering::Equal => return Some(n.val),
            }
        }
        None
    }

    /// Whether `inode` is present.
    #[must_use]
    pub fn contains(&self, inode: u64) -> bool {
        self.get(inode).is_some()
    }

    /// Return a new tree with `inode → block` inserted (or its block updated),
    /// sharing all untouched structure with `self`, which is left unchanged.
    #[must_use]
    pub fn with_inserted(&self, inode: u64, block: u64) -> Self {
        let (root, added) = insert(self.root.as_ref(), inode, block);
        Self {
            root: Some(root),
            len: if added { self.len + 1 } else { self.len },
        }
    }

    /// Return a new tree with `inode` removed (a no-op returning an equal tree
    /// if absent), sharing all untouched structure with `self`.
    #[must_use]
    pub fn with_removed(&self, inode: u64) -> Self {
        let (root, removed) = remove(self.root.as_ref(), inode);
        Self {
            root,
            len: if removed { self.len - 1 } else { self.len },
        }
    }

    /// All `(inode, block)` entries in ascending inode order.
    #[must_use]
    pub fn entries(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::with_capacity(self.len);
        collect(self.root.as_ref(), &mut out);
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn insert_lookup_and_len() {
        let mut t = InodeTree::new();
        assert!(t.is_empty());
        for (inode, block) in [(2u64, 100u64), (1, 101), (3, 102)] {
            t = t.with_inserted(inode, block);
        }
        assert_eq!(t.len(), 3);
        assert_eq!(t.get(1), Some(101));
        assert_eq!(t.get(2), Some(100));
        assert_eq!(t.get(3), Some(102));
        assert_eq!(t.get(99), None);
        assert!(t.contains(2));
        assert!(!t.contains(4));
        // Entries come out sorted by inode.
        assert_eq!(t.entries(), alloc::vec![(1, 101), (2, 100), (3, 102)]);
    }

    #[test]
    fn insert_updates_existing_value_without_growing() {
        let t = InodeTree::new().with_inserted(5, 10).with_inserted(5, 20);
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(5), Some(20));
    }

    #[test]
    fn stays_balanced_under_sorted_inserts() {
        // Inserting 1..=1000 in order would make an unbalanced BST degenerate to
        // height 1000; AVL keeps it logarithmic.
        let mut t = InodeTree::new();
        for i in 1..=1000u64 {
            t = t.with_inserted(i, i * 2);
        }
        assert_eq!(t.len(), 1000);
        assert!(t.height() <= 16, "height {} not logarithmic", t.height());
        for i in 1..=1000u64 {
            assert_eq!(t.get(i), Some(i * 2));
        }
    }

    #[test]
    fn remove_all_cases() {
        let mut t = InodeTree::new();
        for i in [50u64, 30, 70, 20, 40, 60, 80, 35] {
            t = t.with_inserted(i, i);
        }
        let start = t.len();
        // Leaf, one-child, and two-child removals.
        t = t.with_removed(35); // leaf
        t = t.with_removed(20); // leaf
        t = t.with_removed(30); // now has one child (40)
        t = t.with_removed(50); // two children (root) → successor 60
        assert_eq!(t.len(), start - 4);
        assert_eq!(t.get(35), None);
        assert_eq!(t.get(50), None);
        // Survivors intact and still ordered.
        assert_eq!(t.get(40), Some(40));
        assert_eq!(t.get(60), Some(60));
        assert_eq!(
            t.entries(),
            alloc::vec![(40, 40), (60, 60), (70, 70), (80, 80)]
        );
        // Removing an absent key is a no-op.
        let same = t.with_removed(999);
        assert_eq!(same.entries(), t.entries());
        assert_eq!(same.len(), t.len());
    }

    #[test]
    fn copy_on_write_leaves_old_tree_untouched() {
        let base = InodeTree::new()
            .with_inserted(10, 1)
            .with_inserted(5, 2)
            .with_inserted(15, 3);
        // Derive two divergent trees; `base` must observe neither change.
        let added = base.with_inserted(7, 4);
        let removed = base.with_removed(5);

        assert_eq!(base.len(), 3);
        assert_eq!(base.get(7), None, "insert leaked into the base tree");
        assert_eq!(base.get(5), Some(2), "remove leaked into the base tree");

        assert_eq!(added.get(7), Some(4));
        assert_eq!(added.len(), 4);
        assert_eq!(removed.get(5), None);
        assert_eq!(removed.len(), 2);
    }

    #[test]
    fn insert_shares_untouched_subtree() {
        // Tree: root 10, left 5, right 15.
        let base = InodeTree::new()
            .with_inserted(10, 1)
            .with_inserted(5, 2)
            .with_inserted(15, 3);
        // Inserting 6 descends left only; the right subtree (node 15) is not on
        // the path and must be shared by Rc, not copied.
        let derived = base.with_inserted(6, 4);
        let base_right = base.root.as_ref().unwrap().right.clone();
        let derived_right = derived.root.as_ref().unwrap().right.clone();
        let (a, b) = (base_right.unwrap(), derived_right.unwrap());
        assert!(
            Rc::ptr_eq(&a, &b),
            "untouched subtree was copied, not shared"
        );
        // But the roots themselves differ (path was copied).
        assert!(!Rc::ptr_eq(
            base.root.as_ref().unwrap(),
            derived.root.as_ref().unwrap()
        ));
    }
}
