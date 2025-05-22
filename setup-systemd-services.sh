#!/bin/bash

# Script to set up systemd services for FMS application
# Run with sudo: sudo bash setup-systemd-services.sh

echo "Setting up FMS systemd services..."

# Copy service files to systemd directory
cp fms-backend.service /etc/systemd/system/
cp fms-frontend.service /etc/systemd/system/

# Reload systemd configuration
systemctl daemon-reload

# Enable services to start on boot
systemctl enable fms-backend.service
systemctl enable fms-frontend.service

# Start services now
systemctl start fms-backend.service
systemctl start fms-frontend.service

# Check status
echo ""
echo "Backend service status:"
systemctl status fms-backend.service --no-pager
echo ""
echo "Frontend service status:"
systemctl status fms-frontend.service --no-pager

echo ""
echo "Setup complete. Services will now start automatically on system boot."
echo ""
echo "Management commands:"
echo "- Start services:    sudo systemctl start fms-backend.service fms-frontend.service"
echo "- Stop services:     sudo systemctl stop fms-frontend.service fms-backend.service"
echo "- Restart services:  sudo systemctl restart fms-backend.service fms-frontend.service"
echo "- View logs:         sudo journalctl -u fms-backend.service -f"
echo "                     sudo journalctl -u fms-frontend.service -f"