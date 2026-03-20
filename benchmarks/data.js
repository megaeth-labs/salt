window.BENCHMARK_DATA = {
  "lastUpdate": 1774005159859,
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
          "id": "45a7a506cc499a77fd3818b87054dd0302427e19",
          "message": "gh page update",
          "timestamp": "2026-03-20T19:06:35+08:00",
          "tree_id": "0b8be74574eab44de1c6b6b1a010ec6388358bae",
          "url": "https://github.com/megaeth-labs/salt/commit/45a7a506cc499a77fd3818b87054dd0302427e19"
        },
        "date": 1774005157187,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "update 10000 KVs/1 threads",
            "value": 137240000,
            "unit": "ns"
          },
          {
            "name": "update 10000 KVs/2 threads",
            "value": 74123000,
            "unit": "ns"
          },
          {
            "name": "update 10000 KVs/4 threads",
            "value": 39935000,
            "unit": "ns"
          },
          {
            "name": "update 10000 KVs/8 threads",
            "value": 23671000,
            "unit": "ns"
          },
          {
            "name": "update 10000 KVs/16 threads",
            "value": 19000000,
            "unit": "ns"
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
          "id": "45a7a506cc499a77fd3818b87054dd0302427e19",
          "message": "gh page update",
          "timestamp": "2026-03-20T19:06:35+08:00",
          "tree_id": "0b8be74574eab44de1c6b6b1a010ec6388358bae",
          "url": "https://github.com/megaeth-labs/salt/commit/45a7a506cc499a77fd3818b87054dd0302427e19"
        },
        "date": 1774005159277,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "update 10000 KVs/1 threads",
            "value": 72867,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/2 threads",
            "value": 134910,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/4 threads",
            "value": 250410,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/8 threads",
            "value": 422450,
            "unit": "elem/s"
          },
          {
            "name": "update 10000 KVs/16 threads",
            "value": 526310,
            "unit": "elem/s"
          }
        ]
      }
    ]
  }
}