window.BENCHMARK_DATA = {
  "lastUpdate": 1773997662847,
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
            "value": 129970000,
            "unit": "ns"
          },
          {
            "name": "update 10000 KVs/2 threads",
            "value": 71333000,
            "unit": "ns"
          },
          {
            "name": "update 10000 KVs/4 threads",
            "value": 42928000,
            "unit": "ns"
          },
          {
            "name": "update 10000 KVs/8 threads",
            "value": 23273000,
            "unit": "ns"
          },
          {
            "name": "update 10000 KVs/16 threads",
            "value": 18998000,
            "unit": "ns"
          }
        ]
      }
    ]
  }
}