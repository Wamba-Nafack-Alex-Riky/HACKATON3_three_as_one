# Project Directory Tree

```
h
│
├── README.md
│
├── config/
│   ├── config.yaml
│   └── whitelist.yaml
│
├── src/
│   │
│   ├── collector/
│   │   ├── log_reader.py
│   │   ├── normalizer.py
│   │   └── integrity.py
│   │
│   ├── detector/
│   │   ├── http_classifier.py
│   │   ├── ssh_rules.py
│   │   ├── network_anomaly.py
│   │   ├── behavior.py
│   │   └── time_windows.py
│   │
│   ├── models/
│   │   ├── train_http.py
│   │   ├── train_network.py
│   │   ├── http_model.pkl
│   │   └── network_model.pkl
│   │
│   ├── scorer/
│   │   ├── risk_scorer.py
│   │   ├── confidence.py
│   │   └── cost_scorer.py
│   │
│   ├── responder/
│   │   ├── decision.py
│   │   ├── firewall.py
│   │   ├── rate_limiter.py
│   │   └── unban.py
│   │
│   ├── degraded/
│   │   ├── deduplicator.py
│   │   ├── late_log.py
│   │   └── silence_detector.py
│   │
│   ├── journal/
│   │   ├── logger.py
│   │   └── schema.py
│   │
│   ├── api/
│   │   ├── app.py
│   │   └── routes.py
│   │
│   └── dashboard/
│       ├── templates/
│       │   └── index.html
│       └── static/
│           └── style.css
│
├── data/
│   └── sample_logs/
│       ├── apache_access_1.csv
│       ├── auth_ssh_1.csv
│       └── network_flows_1.csv
│
├── tests/
│   ├── test_collector.py
│   ├── test_detector.py
│   ├── test_scorer.py
│   ├── test_responder.py
│   ├── test_api.py
│   └── test_false_positives.py
│
├── docs/
│   └── architecture.md
│
├── requirements.txt
└── main.py
```
