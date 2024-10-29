# SALT Development Notes

To accelerate ECC multiplication that sums around twenty points, we overlap the memory prefetching with point additions.

In the `mul_index` function, we use `mm_prefetch` to prefetch the next point to be added, which is a random memory access. 
Using huge pages decreases TLB misses that potentially invalidates an `mm_prefetch`.

To set up, first ensure your machine supports hugepages and verify the allocated number by executing (currently only supported on Linux):

```bash
grep HugePages /proc/meminfo
```

The output looks like:

```bash
~> grep HugePage /proc/meminfo
AnonHugePages:         0 kB
ShmemHugePages:        0 kB
FileHugePages:         0 kB
HugePages_Total:   10240
HugePages_Free:    10240
HugePages_Rsvd:        0
HugePages_Surp:        0
```

This means the system has 10240 2MB hugepages allocated. 

In our case, 1024 hugepages is enough because precomputed table is around 400MB.

You can allocate hugepages by running:
```bash
sudo sysctl -w vm.nr_hugepages=1024
```
Sometimes it fails because the system doesn't have enough continous physical memory. You might want to reboot in that case.

# Verkle Trie 

**This code has not been reviewed and is not safe to use in non-research capacities.**

This is a proof of concept implementation of Verkle Tries. Any and all mistakes made are mine and are not reflective of the protocol.

## Note on Performance

- This new code currently has less benchmarks
- Parallelism is not currently being used, in places where it could be.

## Note on Differences with references

- The code has been intentionally implemented in a different way in most places to check for consistency and any misunderstandings. For example, recursion is not used as much when inserting leaves. This means that the code will be more verbose as we need to compute exactly when the algorithm will stop ahead of time.

- There are intuitively natural differences due to the language being used, for example, BTreeMap is used in places where the python implementation uses a dictionary and then sorts it.

## Minimum Hardware Requirements
- 32/64 bit architecture due to using `as u32` in some cases in the code. 

## About

This implementation references the ethereum research and go-verkle implementations:

-  https://github.com/ethereum/research/blob/master/verkle_trie_eip/verkle_trie.py
-  https://github.com/gballet/go-verkle


## License

MIT/APACHE
