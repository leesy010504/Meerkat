"""ES 인덱스별 매핑과 ILM 정책을 정의한다."""

INDEX_RETENTION_DAYS: dict[str, tuple[int, int]] = {
    "suricata-alert": (7, 30),
    "suricata-flow": (3, 14),
    "suricata-http": (7, 30),
    "suricata-dns": (3, 14),
    "suricata-tls": (3, 14),
    "nginx-access": (7, 30),
}

_COMMON_PROPERTIES = {
    "@timestamp": {"type": "date"},
    "src_ip": {"type": "ip"},
    "dest_ip": {"type": "ip"},
    "src_port": {"type": "integer"},
    "dest_port": {"type": "integer"},
    "proto": {"type": "keyword"},
    "event_type": {"type": "keyword"},
}

_INDEX_SPECIFIC_PROPERTIES: dict[str, dict] = {
    "suricata-alert": {
        "alert": {
            "properties": {
                "signature_id": {"type": "long"},
                "signature": {"type": "keyword"},
                "category": {"type": "keyword"},
                "severity": {"type": "integer"},
            }
        },
        "payload": {"type": "binary"},
        "packet": {"type": "binary"},
    },
    "suricata-flow": {
        "flow": {
            "properties": {
                "pkts_toserver": {"type": "long"},
                "pkts_toclient": {"type": "long"},
                "bytes_toserver": {"type": "long"},
                "bytes_toclient": {"type": "long"},
                "age": {"type": "integer"},
                "state": {"type": "keyword"},
            }
        }
    },
    "suricata-http": {
        "http": {
            "properties": {
                "hostname": {"type": "keyword"},
                "url": {"type": "keyword"},
                "http_method": {"type": "keyword"},
                "http_user_agent": {"type": "keyword"},
                "status": {"type": "integer"},
                "http_content_type": {"type": "keyword"},
                "length": {"type": "long"},
                "http_headers_raw": {"type": "text", "index": False},
            }
        }
    },
    "suricata-dns": {
        "dns": {
            "properties": {
                "rrname": {"type": "keyword"},
                "rrtype": {"type": "keyword"},
                "rcode": {"type": "keyword"},
                "answers_count": {"type": "integer"},
            }
        }
    },
    "suricata-tls": {
        "tls": {
            "properties": {
                "sni": {"type": "keyword"},
                "version": {"type": "keyword"},
                "ja3": {"properties": {"hash": {"type": "keyword"}}},
                "cert_raw": {"type": "binary"},
            }
        }
    },
    "nginx-access": {
        "nginx": {
            "properties": {
                "path": {"type": "keyword"},
                "status": {"type": "integer"},
                "request_time": {"type": "float"},
                "raw_line": {"type": "text", "index": False},
            }
        }
    },
}


def build_ilm_policy(index_name: str, hot_days: int, warm_days: int) -> dict:
    return {
        "policy": {
            "phases": {
                "hot": {
                    "min_age": "0ms",
                    "actions": {"rollover": {"max_age": f"{hot_days}d"}},
                },
                "warm": {
                    "min_age": f"{hot_days}d",
                    "actions": {
                        "forcemerge": {"max_num_segments": 1},
                        "shrink": {"number_of_shards": 1},
                        "readonly": {},
                    },
                },
                "delete": {
                    "min_age": f"{hot_days + warm_days}d",
                    "actions": {"delete": {}},
                },
            }
        }
    }


def build_index_template(index_name: str) -> dict:
    hot_days, warm_days = INDEX_RETENTION_DAYS[index_name]
    properties = {**_COMMON_PROPERTIES, **_INDEX_SPECIFIC_PROPERTIES.get(index_name, {})}

    return {
        "index_patterns": [f"{index_name}-*"],
        "template": {
            "settings": {
                "index.lifecycle.name": f"{index_name}-ilm",
                "index.codec": "best_compression",
            },
            "mappings": {"properties": properties},
        },
    }


def build_all_templates() -> dict[str, dict]:
    return {name: build_index_template(name) for name in INDEX_RETENTION_DAYS}


def build_all_ilm_policies() -> dict[str, dict]:
    return {
        name: build_ilm_policy(name, hot_days, warm_days)
        for name, (hot_days, warm_days) in INDEX_RETENTION_DAYS.items()
    }
