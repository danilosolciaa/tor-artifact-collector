#!/bin/bash
# Tor Forensic Collector - Demo Script
# Runs the tool in demo mode (uses mock data, no real artifacts required)

echo "========================================"
echo "Tor Forensic Collector - Demo Mode"
echo "NFI Internship Application 2025"
echo "========================================"
echo ""

# Ensure we're in the project root
cd "$(dirname "$0")/.." || exit 1

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed or not in PATH"
    exit 1
fi

echo "Step 1: Installing dependencies (demo mode only, no Windows libraries needed)"
echo "-------------------------------------------"
# In demo mode, we don't actually need yarp, python-evtx, or windowsprefetch
# because we use mock data. For production, uncomment the line below:
# pip install -e .

echo ""
echo "Step 2: Running forensic collector in DEMO mode"
echo "-------------------------------------------"
python3 -m src.cli \
    --demo \
    --output examples/demo_timeline.json \
    --format json \
    --pretty \
    --stats \
    --verbose

echo ""
echo "========================================"
echo "Demo Complete!"
echo "========================================"
echo ""
echo "Output file: examples/demo_timeline.json"
echo ""
echo "To view the timeline:"
echo "  cat examples/demo_timeline.json"
echo ""
echo "To run with real artifacts (requires Windows):"
echo "  python3 -m src.cli --ntuser C:\\Users\\YourUser\\NTUSER.DAT --places C:\\path\\to\\places.sqlite"
echo ""
