window.BENCHMARK_DATA = {
  "lastUpdate": 1773998990554,
  "repoUrl": "https://github.com/megaeth-labs/salt",
  "entries": {
    "salt-benchmark-time": [
      {
        "commit": {
          "author": {
            "email": "yunlong@megaeth.technology",
            "name": "yunlonggao-mega",
            "username": "yunlonggao-mega"
          },
          "committer": {
            "email": "yunlong@megaeth.technology",
            "name": "yunlonggao-mega",
            "username": "yunlonggao-mega"
          },
          "distinct": true,
          "id": "923fdcbb25c56d338e6833b39f766d1e77c17f33",
          "message": "init baseline data",
          "timestamp": "2026-03-20T16:56:45+08:00",
          "tree_id": "3b21fdb6e1876e230d358348edd1f66a1bf2f706",
          "url": "https://github.com/megaeth-labs/salt/commit/923fdcbb25c56d338e6833b39f766d1e77c17f33"
        },
        "date": 1773997661666,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "update 10000 KVs/1 threads",
            "value": 129.97,
            "unit": "ms"
          },
          {
            "name": "update 10000 KVs/2 threads",
            "value": 71.333,
            "unit": "ms"
          },
          {
            "name": "update 10000 KVs/4 threads",
            "value": 42.928,
            "unit": "ms"
          },
          {
            "name": "update 10000 KVs/8 threads",
            "value": 23.273,
            "unit": "ms"
          },
          {
            "name": "update 10000 KVs/16 threads",
            "value": 18.998,
            "unit": "ms"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yunlong@megaeth.technology",
            "name": "yunlonggao-mega",
            "username": "yunlonggao-mega"
          },
          "committer": {
            "email": "yunlong@megaeth.technology",
            "name": "yunlonggao-mega",
            "username": "yunlonggao-mega"
          },
          "distinct": true,
          "id": "b277083bacab2be12133306b3633152c49005dcc",
          "message": "update toolchain version",
          "timestamp": "2026-03-20T17:25:42+08:00",
          "tree_id": "f49bd1a68e0d9e1ab7a9bc1e2433ad8dd2ba8467",
          "url": "https://github.com/megaeth-labs/salt/commit/b277083bacab2be12133306b3633152c49005dcc"
        },
        "date": 1773998987709,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "update 10000 KVs/1 threads",
            "value": 124.3,
            "unit": "ms"
          },
          {
            "name": "update 10000 KVs/2 threads",
            "value": 66.269,
            "unit": "ms"
          },
          {
            "name": "update 10000 KVs/4 threads",
            "value": 37.451,
            "unit": "ms"
          },
          {
            "name": "update 10000 KVs/8 threads",
            "value": 24.955,
            "unit": "ms"
          },
          {
            "name": "update 10000 KVs/16 threads",
            "value": 24.261,
            "unit": "ms"
          }
        ]
      }
    ],
    "salt-benchmark-throughput": [
      {
        "commit": {
          "author": {
            "email": "yunlong@megaeth.technology",
            "name": "yunlonggao-mega",
            "username": "yunlonggao-mega"
          },
          "committer": {
            "email": "yunlong@megaeth.technology",
            "name": "yunlonggao-mega",
            "username": "yunlonggao-mega"
          },
          "distinct": true,
          "id": "923fdcbb25c56d338e6833b39f766d1e77c17f33",
          "message": "init baseline data",
          "timestamp": "2026-03-20T16:56:45+08:00",
          "tree_id": "3b21fdb6e1876e230d358348edd1f66a1bf2f706",
          "url": "https://github.com/megaeth-labs/salt/commit/923fdcbb25c56d338e6833b39f766d1e77c17f33"
        },
        "date": 1773997663674,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "update 10000 KVs/1 threads",
            "value": 76941,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/2 threads",
            "value": 140190,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/4 threads",
            "value": 232950,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/8 threads",
            "value": 429680,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/16 threads",
            "value": 526370,
            "unit": "elem/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yunlong@megaeth.technology",
            "name": "yunlonggao-mega",
            "username": "yunlonggao-mega"
          },
          "committer": {
            "email": "yunlong@megaeth.technology",
            "name": "yunlonggao-mega",
            "username": "yunlonggao-mega"
          },
          "distinct": true,
          "id": "b277083bacab2be12133306b3633152c49005dcc",
          "message": "update toolchain version",
          "timestamp": "2026-03-20T17:25:42+08:00",
          "tree_id": "f49bd1a68e0d9e1ab7a9bc1e2433ad8dd2ba8467",
          "url": "https://github.com/megaeth-labs/salt/commit/b277083bacab2be12133306b3633152c49005dcc"
        },
        "date": 1773998989960,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "update 10000 KVs/1 threads",
            "value": 80449,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/2 threads",
            "value": 150900,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/4 threads",
            "value": 267020,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/8 threads",
            "value": 400720,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/16 threads",
            "value": 412190,
            "unit": "elem/s"
          }
        ]
      }
    ]
  }
}
