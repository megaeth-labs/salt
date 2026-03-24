window.BENCHMARK_DATA = {
  "lastUpdate": 1774318475876,
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
          "id": "00b9a5f546aae5477e3e212081e66dd6d5586eec",
          "message": "print cpu info",
          "timestamp": "2026-03-24T10:10:22+08:00",
          "tree_id": "c3bfc9764364ad808d329d690382dc85c0e3d1f2",
          "url": "https://github.com/megaeth-labs/salt/commit/00b9a5f546aae5477e3e212081e66dd6d5586eec"
        },
        "date": 1774318472827,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "update 10000 KVs/1 threads",
            "value": 125.25,
            "unit": "ms"
          },
          {
            "name": "update 10000 KVs/2 threads",
            "value": 66.396,
            "unit": "ms"
          },
          {
            "name": "update 10000 KVs/4 threads",
            "value": 36.969,
            "unit": "ms"
          },
          {
            "name": "update 10000 KVs/8 threads",
            "value": 23.47,
            "unit": "ms"
          },
          {
            "name": "update 10000 KVs/16 threads",
            "value": 20.925,
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
          "id": "00b9a5f546aae5477e3e212081e66dd6d5586eec",
          "message": "print cpu info",
          "timestamp": "2026-03-24T10:10:22+08:00",
          "tree_id": "c3bfc9764364ad808d329d690382dc85c0e3d1f2",
          "url": "https://github.com/megaeth-labs/salt/commit/00b9a5f546aae5477e3e212081e66dd6d5586eec"
        },
        "date": 1774318475201,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "update 10000 KVs/1 threads",
            "value": 79840,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/2 threads",
            "value": 150610,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/4 threads",
            "value": 270500,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/8 threads",
            "value": 426080,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/16 threads",
            "value": 477900,
            "unit": "elem/s"
          }
        ]
      }
    ]
  }
}