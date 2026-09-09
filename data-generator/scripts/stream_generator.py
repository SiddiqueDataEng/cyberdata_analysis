#!/usr/bin/env python3
"""
Live Streaming Data Generator for Cybersecurity Data Engineering
Generates continuous, realistic security data streams with:
- Realistic time-of-day traffic shaping
- Burst simulation
- Full attack scenario injection
- Kafka, Redis, Logstash, and file output
- Covers Ch 4-10, 13 data requirements
"""

import json
import random
import datetime
import time
import threading
import queue
import signal
import sys
import os
from pathlib import Path
from typing import Dict, Any, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generate_historical import DataGenerator, LogGenerator, HistoricalDataGenerator

# ==================== CONFIGURATION ====================

STREAM_CONFIG = {
    "output_destinations": {
        "stdout": os.environ.get("STDOUT", "false").lower() == "true",
        "file": True,
        "kafka": os.environ.get("KAFKA_ENABLED", "false").lower() == "true",
        "redis": os.environ.get("REDIS_ENABLED", "false").lower() == "true",
        "logstash": os.environ.get("LOGSTASH_ENABLED", "false").lower() == "true"
    },
    "output_dir": os.environ.get("OUTPUT_DIR", "../streaming_data/"),
    "run_duration_hours": float(os.environ.get("RUN_DURATION_HOURS", "0")),
    "log_rate": {
        "low": int(os.environ.get("LOG_RATE_LOW", "50")),
        "medium": int(os.environ.get("LOG_RATE_MEDIUM", "200")),
        "high": int(os.environ.get("LOG_RATE_HIGH", "1000")),
        "burst": 5000
    },
    "kafka": {
        "bootstrap_servers": os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092"),
        "topic_map": {
            "windows": "security-windows",
            "sysmon": "security-windows",
            "powershell": "security-windows",
            "linux_syslog": "security-linux",
            "rsyslog_structured": "security-linux",
            "network": "security-network",
            "zeek_dns": "security-network",
            "suricata": "security-network",
            "firewall": "security-network",
            "application": "security-application",
            "threat_intel": "threat-intel",
            "kafka_pipeline": "security-all",
            "logstash_enriched": "security-enriched"
        }
    },
    "redis": {
        "host": os.environ.get("REDIS_HOST", "redis"),
        "port": int(os.environ.get("REDIS_PORT", "6379")),
        "password": os.environ.get("REDIS_PASSWORD", ""),
        "stream_key": "security:stream"
    },
    "logstash": {
        "host": os.environ.get("LOGSTASH_HOST", "logstash"),
        "port": int(os.environ.get("LOGSTASH_PORT", "8080"))
    }
}

# Attack scenario injection schedule (minutes after start)
ATTACK_SCHEDULE = [
    (15, "apt"),
    (30, "ransomware"),
    (45, "data_exfil"),
    (60, "cred_theft")
]


# ==================== OUTPUT HANDLERS ====================

class FileOutput:
    def __init__(self, output_dir: str):
        self.path = Path(output_dir)
        self.path.mkdir(parents=True, exist_ok=True)
        fname = f"stream_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.ndjson"
        self.file = open(self.path / fname, "w", encoding="utf-8")
        print(f"File output: {self.path / fname}")

    def write(self, event: Dict):
        self.file.write(json.dumps(event) + "\n")
        self.file.flush()

    def close(self):
        if self.file:
            self.file.close()


class KafkaOutput:
    def __init__(self, config: Dict):
        self.config = config
        self.producer = None
        self.topic_map = config["topic_map"]
        self._connect()

    def _connect(self):
        try:
            from kafka import KafkaProducer
            self.producer = KafkaProducer(
                bootstrap_servers=self.config["bootstrap_servers"],
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                acks=1,
                compression_type="gzip",
                max_block_ms=5000
            )
            print(f"Kafka output: {self.config['bootstrap_servers']}")
        except ImportError:
            print("Warning: kafka-python not installed. Kafka output disabled.")
        except Exception as e:
            print(f"Warning: Kafka connection failed: {e}. Kafka output disabled.")

    def write(self, event: Dict):
        if not self.producer:
            return
        dataset = event.get("event", {}).get("dataset", "security-all")
        log_type = dataset.split(".")[0] if "." in dataset else "security-all"
        topic = self.topic_map.get(log_type, "security-all")
        try:
            self.producer.send(topic, value=event)
        except Exception as e:
            print(f"Kafka write error: {e}")

    def close(self):
        if self.producer:
            self.producer.flush()
            self.producer.close()


class RedisOutput:
    def __init__(self, config: Dict):
        self.config = config
        self.client = None
        self._connect()

    def _connect(self):
        try:
            import redis
            self.client = redis.Redis(
                host=self.config["host"],
                port=self.config["port"],
                password=self.config["password"] or None,
                decode_responses=True,
                socket_connect_timeout=5
            )
            self.client.ping()
            print(f"Redis output: {self.config['host']}:{self.config['port']}")
        except ImportError:
            print("Warning: redis-py not installed. Redis output disabled.")
            self.client = None
        except Exception as e:
            print(f"Warning: Redis connection failed: {e}. Redis output disabled.")
            self.client = None

    def write(self, event: Dict):
        if not self.client:
            return
        try:
            # Use Redis Streams (XADD) for ordered, persistent event stream
            self.client.xadd(
                self.config["stream_key"],
                {"data": json.dumps(event)},
                maxlen=100000  # Keep last 100k events
            )
        except Exception as e:
            print(f"Redis write error: {e}")

    def close(self):
        pass  # redis-py manages connection pool


class LogstashOutput:
    def __init__(self, config: Dict):
        self.config = config
        self.url = f"http://{config['host']}:{config['port']}"
        self.session = None
        self._connect()

    def _connect(self):
        try:
            import urllib.request
            # Test connectivity
            req = urllib.request.Request(f"{self.url}/health", method="GET")
            try:
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass  # Logstash HTTP input may not have /health
            self.session = True
            print(f"Logstash output: {self.url}")
        except Exception as e:
            print(f"Warning: Logstash not reachable: {e}")

    def write(self, event: Dict):
        if not self.session:
            return
        try:
            import urllib.request
            data = json.dumps(event).encode("utf-8")
            req = urllib.request.Request(
                self.url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass  # Best-effort, don't block stream

    def close(self):
        pass


# ==================== STREAM GENERATOR ====================

class StreamGenerator:

    LOG_WEIGHTS = {
        "network": 0.18, "zeek_dns": 0.08, "suricata": 0.05,
        "windows": 0.14, "sysmon": 0.10, "powershell": 0.03,
        "linux_syslog": 0.14, "rsyslog_structured": 0.04,
        "firewall": 0.08, "threat_intel": 0.04,
        "application": 0.08, "kafka_pipeline": 0.02, "logstash_enriched": 0.02
    }

    def __init__(self, config: Dict = None):
        self.config = config or STREAM_CONFIG
        self.gen = DataGenerator()
        self.log_gen = LogGenerator(self.gen)
        self.hist_gen = HistoricalDataGenerator()
        self.running = False
        self.event_count = 0
        self.start_time: Optional[datetime.datetime] = None
        self.output_queue: queue.Queue = queue.Queue(maxsize=20000)
        self.outputs: List = []
        self._attack_queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()

        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        self.running = False

    def _setup_outputs(self):
        if self.config["output_destinations"]["file"]:
            self.outputs.append(FileOutput(self.config["output_dir"]))
        if self.config["output_destinations"]["kafka"]:
            self.outputs.append(KafkaOutput(self.config["kafka"]))
        if self.config["output_destinations"]["redis"]:
            self.outputs.append(RedisOutput(self.config["redis"]))
        if self.config["output_destinations"]["logstash"]:
            self.outputs.append(LogstashOutput(self.config["logstash"]))

    def _get_current_rate(self) -> int:
        """Simulate realistic traffic patterns based on time of day."""
        hour = datetime.datetime.now().hour
        if 9 <= hour < 17:    # Business hours – high
            return self.config["log_rate"]["high"]
        elif 17 <= hour < 20:  # Early evening – medium
            return self.config["log_rate"]["medium"]
        elif 6 <= hour < 9 or 20 <= hour < 23:
            return self.config["log_rate"]["low"]
        else:                  # Late night / early morning – minimal
            return max(10, self.config["log_rate"]["low"] // 5)

    def _should_burst(self) -> bool:
        return random.random() < 0.015  # ~1.5% chance per tick

    def _pick_log_type(self) -> str:
        return random.choices(
            list(self.LOG_WEIGHTS.keys()),
            weights=list(self.LOG_WEIGHTS.values())
        )[0]

    def _generate_event(self) -> Dict[str, Any]:
        ts = datetime.datetime.now(datetime.timezone.utc)
        self.log_gen.set_timestamp(ts)

        dispatch = {
            "network": self.log_gen.generate_network_log,
            "zeek_dns": self.log_gen.generate_zeek_dns,
            "suricata": self.log_gen.generate_suricata_alert,
            "windows": self.log_gen.generate_windows_event,
            "sysmon": self.log_gen.generate_sysmon_event,
            "powershell": self.log_gen.generate_powershell_scriptblock,
            "linux_syslog": self.log_gen.generate_linux_syslog,
            "rsyslog_structured": self.log_gen.generate_rsyslog_structured,
            "firewall": self.log_gen.generate_firewall_log,
            "threat_intel": self.log_gen.generate_threat_intel_feed,
            "application": self.log_gen.generate_application_log,
            "kafka_pipeline": self.log_gen.generate_kafka_pipeline_event,
            "logstash_enriched": self.log_gen.generate_logstash_enriched
        }

        log_type = self._pick_log_type()
        event = dispatch[log_type]()
        with self._lock:
            event["stream"] = {
                "sequence": self.event_count,
                "log_type": log_type,
                "ingestion_time": ts.isoformat()
            }
        return event

    def _producer_worker(self):
        last_time = time.monotonic()
        burst_mode = False
        burst_end = 0.0

        while self.running:
            now = time.monotonic()

            # Check for burst
            if not burst_mode and self._should_burst():
                burst_mode = True
                duration = random.uniform(1.0, 8.0)
                burst_end = now + duration
                print(f"  [BURST] Traffic spike starting ({duration:.1f}s)")

            if burst_mode and now >= burst_end:
                burst_mode = False
                print("  [BURST] Traffic normalizing")

            rate = self.config["log_rate"]["burst"] if burst_mode else self._get_current_rate()
            interval = 1.0 / max(1, rate)

            # Check if attack events are queued
            while not self._attack_queue.empty():
                try:
                    attack_event = self._attack_queue.get_nowait()
                    self.output_queue.put(attack_event, timeout=0.5)
                    with self._lock:
                        self.event_count += 1
                except (queue.Empty, queue.Full):
                    break

            # Generate normal event
            try:
                event = self._generate_event()
                self.output_queue.put(event, timeout=0.5)
                with self._lock:
                    self.event_count += 1
            except queue.Full:
                pass  # Drop rather than block

            # Rate limiting
            sleep_time = max(0.0, (last_time + interval) - time.monotonic())
            if sleep_time > 0:
                time.sleep(sleep_time)
            last_time = time.monotonic()

    def _consumer_worker(self):
        while self.running or not self.output_queue.empty():
            try:
                event = self.output_queue.get(timeout=0.5)

                # Write to all configured outputs
                for output in self.outputs:
                    output.write(event)

                # stdout if enabled
                if self.config["output_destinations"]["stdout"]:
                    print(json.dumps(event))

                self.output_queue.task_done()
            except queue.Empty:
                if not self.running:
                    break

    def _attack_scheduler(self):
        """Schedule attack scenario injection during the stream."""
        if not self.start_time:
            return
        for delay_minutes, scenario in ATTACK_SCHEDULE:
            if not self.running:
                break
            target_time = self.start_time + datetime.timedelta(minutes=delay_minutes)
            wait_secs = (target_time - datetime.datetime.now()).total_seconds()
            if wait_secs > 0:
                time.sleep(wait_secs)
            if not self.running:
                break
            print(f"\n  [ATTACK] Injecting scenario: {scenario}")
            self._inject_attack_scenario(scenario)

    def _inject_attack_scenario(self, scenario: str):
        """Generate and queue attack scenario events."""
        date = datetime.datetime.now()
        dispatch = {
            "apt": self.hist_gen._scenario_apt,
            "ransomware": self.hist_gen._scenario_ransomware,
            "data_exfil": self.hist_gen._scenario_data_exfiltration,
            "cred_theft": self.hist_gen._scenario_credential_theft
        }
        fn = dispatch.get(scenario, self.hist_gen._scenario_apt)
        events = fn(date)
        for event in events:
            try:
                self._attack_queue.put_nowait(event)
            except queue.Full:
                break
        print(f"  [ATTACK] Queued {len(events)} events for '{scenario}' scenario")

    def _stats_monitor(self):
        last_count = 0
        last_time = time.monotonic()
        while self.running:
            time.sleep(10)
            now = time.monotonic()
            elapsed = now - last_time
            with self._lock:
                current = self.event_count
            delta = current - last_count
            rate = delta / elapsed if elapsed > 0 else 0
            print(
                f"[{datetime.datetime.now().strftime('%H:%M:%S')}] "
                f"Total: {current:,}  |  Rate: {rate:.0f}/s  |  "
                f"Queue: {self.output_queue.qsize():,}"
            )
            last_count = current
            last_time = now

    def start(self):
        self.running = True
        self.start_time = datetime.datetime.now()
        self.event_count = 0

        self._setup_outputs()

        threads = [
            threading.Thread(target=self._consumer_worker, daemon=True, name="consumer"),
            threading.Thread(target=self._producer_worker, daemon=True, name="producer"),
            threading.Thread(target=self._stats_monitor, daemon=True, name="stats"),
            threading.Thread(target=self._attack_scheduler, daemon=True, name="attack-scheduler")
        ]
        for t in threads:
            t.start()

        rate = self._get_current_rate()
        print(f"Stream generator started at {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Initial rate: ~{rate} events/second")
        print(f"Attack scenarios scheduled at: {[f'{m}min ({s})' for m, s in ATTACK_SCHEDULE]}\n")

        # Duration control
        duration = self.config["run_duration_hours"]
        if duration > 0:
            end_time = self.start_time + datetime.timedelta(hours=duration)
            while self.running and datetime.datetime.now() < end_time:
                time.sleep(1)
            self.running = False
        else:
            # Run until signal
            while self.running:
                time.sleep(1)

    def stop(self):
        self.running = False
        # Drain queue
        time.sleep(2)
        for output in self.outputs:
            output.close()
        print(f"\nStream stopped. Total events generated: {self.event_count:,}")


# ==================== SCENARIO GENERATORS ====================
# These expose the attack scenarios as standalone generators
# for use in testing specific detection rules (Ch 13 threat intel)

class ScenarioGenerator:

    def __init__(self):
        self._hist = HistoricalDataGenerator()

    def ransomware_scenario(self) -> List[Dict[str, Any]]:
        """Simulate a ransomware attack — use for testing SIEM detection rules."""
        return self._hist._scenario_ransomware(datetime.datetime.now())

    def data_exfiltration_scenario(self) -> List[Dict[str, Any]]:
        """Simulate DNS-tunnelling data exfiltration — tests DNS monitoring (Ch 7)."""
        return self._hist._scenario_data_exfiltration(datetime.datetime.now())

    def credential_theft_scenario(self) -> List[Dict[str, Any]]:
        """Simulate credential theft via LSASS dump and Kerberoasting (Ch 5, 13)."""
        return self._hist._scenario_credential_theft(datetime.datetime.now())

    def apt_scenario(self) -> List[Dict[str, Any]]:
        """Simulate full APT kill chain (Ch 4–10)."""
        return self._hist._scenario_apt(datetime.datetime.now())

    def threat_intel_feed_batch(self, count: int = 100) -> List[Dict[str, Any]]:
        """
        Generate a batch of threat intel indicators for populating Redis/Memcached
        (Ch 13 – caching threat intelligence).
        Returns events ready for Logstash → Redis pipeline.
        """
        log_gen = LogGenerator(self._hist.generator)
        log_gen.set_timestamp(datetime.datetime.utcnow())
        return [log_gen.generate_threat_intel_feed() for _ in range(count)]

    def redis_threat_kv_pairs(self, count: int = 100) -> Dict[str, str]:
        """
        Generate key-value pairs for direct Redis HSET population (Ch 13).
        Returns {indicator_value: json_metadata} dict.
        """
        indicators = self.threat_intel_feed_batch(count)
        kv = {}
        for ind in indicators:
            ti = ind.get("threat", {}).get("indicator", {})
            val = ti.get("ip") or ti.get("domain") or (ti.get("file") or {}).get("hash", {}).get("sha256") or ti.get("url", {}).get("full")
            if val:
                kv[val] = json.dumps({
                    "severity": ti.get("description", ""),
                    "provider": ti.get("provider", ""),
                    "confidence": ti.get("confidence", 0),
                    "type": ti.get("type", "")
                })
        return kv


# ==================== MAIN ====================

if __name__ == "__main__":
    print("=== Cybersecurity Data Engineering - Live Stream Generator ===\n")
    generator = StreamGenerator()
    try:
        generator.start()
    finally:
        generator.stop()
