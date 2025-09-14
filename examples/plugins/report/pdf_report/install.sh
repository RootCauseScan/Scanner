#!/bin/bash
# Installation script for PDF Report Plugin

set -e

echo "Installing PDF Report Plugin dependencies..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Use the virtual environment's pip directly instead of activating
echo "Using virtual environment pip..."
VENV_PIP="./venv/bin/pip"
VENV_PYTHON="./venv/bin/python"

# Upgrade pip using the virtual environment's pip
echo "Upgrading pip..."
$VENV_PIP install --upgrade pip

# Install dependencies
echo "Installing dependencies from requirements.txt..."
$VENV_PIP install -r requirements.txt

# Create a wrapper script that uses the virtual environment's python directly
echo "Creating plugin wrapper..."
cat > plugin_wrapper.sh << 'EOF'
#!/bin/bash
# Wrapper script to run the plugin with virtual environment
cd "$(dirname "$0")"
exec ./venv/bin/python plugin.py "$@"
EOF

chmod +x plugin_wrapper.sh

echo "Installation completed successfully!"
echo "Plugin can be run using: ./plugin_wrapper.sh"
