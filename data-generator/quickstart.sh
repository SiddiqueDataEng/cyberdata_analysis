#!/bin/bash
# Quick start script for the cybersecurity data engineering pipeline

set -e

echo "=========================================="
echo "Cybersecurity Data Engineering Pipeline"
echo "=========================================="

# Check prerequisites
echo "Checking prerequisites..."
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting." >&2; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "docker-compose is required but not installed. Aborting." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Python3 is required but not installed. Aborting." >&2; exit 1; }

# Create directories
echo "Creating directories..."
mkdir -p data/{historical_data,streaming_data,windows_logs,filebeat_output}
mkdir -p config/logstash
mkdir -p monitoring

# Generate historical data
echo "Generating historical data..."
python3 data-generator/scripts/generate_historical.py

# Start streaming generator in background
echo "Starting live stream generator..."
python3 data-generator/scripts/stream_generator.py &
STREAM_PID=$!

# Start the pipeline
echo "Starting data pipeline..."
docker-compose up -d

echo ""
echo "Pipeline started successfully!"
echo ""
echo "Access the following services:"
echo "  - Kibana: http://localhost:5601"
echo "  - Kafka UI: http://localhost:8085"
echo "  - Grafana: http://localhost:3000 (admin/admin)"
echo "  - Prometheus: http://localhost:9090"
echo ""
echo "Data locations:"
echo "  - Historical: ./data/historical_data/"
echo "  - Streaming: ./data/streaming_data/"
echo ""
echo "To stop the pipeline:"
echo "  - docker-compose down"
echo "  - kill $STREAM_PID"
echo ""
echo "Monitor logs:"
echo "  - docker-compose logs -f logstash"