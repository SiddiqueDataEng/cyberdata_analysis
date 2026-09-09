"""
Generate 2GB+ additional historical data.
Extends coverage: 2024-01-31 → 2024-07-31 (6 more months)
with 20000 events/day → ~180 days × 20k = 3.6M events ≈ 2-3 GB
"""
import os, sys, random, datetime
sys.path.insert(0, "data-generator/scripts")

os.environ["OUTPUT_DIR"]      = "E:/Cyberdata/historical_data/"
os.environ["EVENTS_PER_DAY"]  = "20000"
os.environ["DAYS_TO_GENERATE"]= "180"
os.environ["START_DATE"]      = "2024-02-01"

from generate_historical import HistoricalDataGenerator
import datetime as dt

print("Generating 180 days × 20,000 events/day (~3.6M events, ~2-3 GB)...")
gen = HistoricalDataGenerator()

start = dt.datetime(2024, 2, 1)

# Extra attack scenarios spread across the period
attack_scenarios = [
    (dt.datetime(2024, 2, 14), "apt"),
    (dt.datetime(2024, 3, 7),  "ransomware"),
    (dt.datetime(2024, 3, 22), "cred_theft"),
    (dt.datetime(2024, 4, 3),  "data_exfil"),
    (dt.datetime(2024, 4, 18), "apt"),
    (dt.datetime(2024, 5, 1),  "ransomware"),
    (dt.datetime(2024, 5, 15), "cred_theft"),
    (dt.datetime(2024, 6, 2),  "data_exfil"),
    (dt.datetime(2024, 6, 20), "apt"),
    (dt.datetime(2024, 7, 4),  "ransomware"),
    (dt.datetime(2024, 7, 18), "cred_theft"),
]

attack_dates = {d.date() for d, _ in attack_scenarios}

for i in range(180):
    day = start + dt.timedelta(days=i)
    gen.generate_day(day, events_per_day=20000)
    # Inject attack on specific days
    if day.date() in attack_dates:
        for aday, scenario in attack_scenarios:
            if aday.date() == day.date():
                gen.generate_attack_scenario(day, scenario)

print("\nDone! Check historical_data/ for new files.")
