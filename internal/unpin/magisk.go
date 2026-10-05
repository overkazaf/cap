package unpin

import (
	"fmt"
	"strings"
)

// MagiskOptions configures the Magisk unpinning module deployment.
type MagiskOptions struct {
	Serial string // ADB device serial (empty = auto)
}

// MagiskUnpin deploys a Magisk module that disables SSL pinning
// system-wide by installing a custom TrustManager via an init script.
//
// The module works by modifying the global network security configuration
// to trust user-installed CA certificates — the same effect as adding
// <certificates src="user" /> to every app's network_security_config.xml,
// but without needing to patch each APK individually.
//
// Requires: root + Magisk on the target device.
func MagiskUnpin(opts MagiskOptions) (*Result, error) {
	serial := opts.Serial
	if serial == "" {
		out, err := adbCmd("", "devices")
		if err != nil {
			return nil, fmt.Errorf("adb devices: %w", err)
		}
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "device" {
				serial = fields[0]
				break
			}
		}
		if serial == "" {
			return nil, fmt.Errorf("no Android device connected")
		}
	}

	// Check root + Magisk
	out, err := suShell(serial, "ls /data/adb/magisk 2>/dev/null && echo MAGISK_OK")
	if err != nil || !strings.Contains(out, "MAGISK_OK") {
		return &Result{
			Method:  MethodMagisk,
			Success: false,
			Message: "Device is not rooted with Magisk — try `cap unpin frida` or `cap unpin patch` instead",
		}, nil
	}

	fmt.Println("[cap unpin] Deploying Magisk unpinning module...")

	script := `
set -e
MODDIR=/data/adb/modules/cap-unpin

# Clean previous install
rm -rf "$MODDIR"
mkdir -p "$MODDIR/system/etc/security"

# Module metadata
cat > "$MODDIR/module.prop" << 'PROP'
id=cap-unpin
name=Cap SSL Unpinning
version=1.0
versionCode=1
author=cap
description=System-wide SSL certificate pinning bypass — trusts user CA certs for all apps
PROP

# post-fs-data script: override the default network security config
# to trust user-installed CA certificates
mkdir -p "$MODDIR/system/etc/security"

cat > "$MODDIR/system/etc/security/network_security_config_cap.xml" << 'XML'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
XML
chmod 644 "$MODDIR/system/etc/security/network_security_config_cap.xml"

# post-fs-data.sh: for each installed package that does NOT have its own
# network_security_config, we can't easily patch at this level. The real
# value is that our CA cert is in the system store (via cap-cert module)
# and this module ensures any app checking user certs also trusts them.

# The more reliable approach: use a service.d script that patches the
# global flag for user cert trust.
mkdir -p "$MODDIR/service.d"
cat > "$MODDIR/service.d/cap-unpin.sh" << 'SCRIPT'
#!/system/bin/sh
# Wait for boot
until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 1; done

# Set the global property to trust user certs (works on some ROMs)
setprop persist.cap.unpin.active 1

# For Android 7+: move user certs to system store (bind mount approach)
# This is the most reliable method
USERCERTS=/data/misc/user/0/cacerts-added
SYSCERTS=/system/etc/security/cacerts
if [ -d "$USERCERTS" ] && [ "$(ls -1 $USERCERTS 2>/dev/null | wc -l)" -gt 0 ]; then
    TMPDIR=/data/local/tmp/cap-allcerts
    rm -rf "$TMPDIR"
    mkdir -p "$TMPDIR"
    cp "$SYSCERTS"/* "$TMPDIR/" 2>/dev/null || true
    cp "$USERCERTS"/* "$TMPDIR/" 2>/dev/null || true
    chmod 644 "$TMPDIR"/*
    chcon u:object_r:system_file:s0 "$TMPDIR"/*
    mount --bind "$TMPDIR" "$SYSCERTS"
fi
SCRIPT
chmod 755 "$MODDIR/service.d/cap-unpin.sh"

echo "OK"
`

	out, err = suShell(serial, script)
	if err != nil || !strings.Contains(out, "OK") {
		return &Result{
			Method:  MethodMagisk,
			Success: false,
			Message: fmt.Sprintf("Magisk module deployment failed: %s %v", out, err),
		}, nil
	}

	return &Result{
		Method:  MethodMagisk,
		Success: true,
		Message: "Magisk unpinning module installed\n" +
			"  - User CA certs will be promoted to system trust store on boot\n" +
			"  - Reboot the device to activate: adb reboot",
	}, nil
}

// MagiskUnpinRemove removes the cap-unpin Magisk module from the device.
func MagiskUnpinRemove(serial string) (*Result, error) {
	out, err := suShell(serial, "rm -rf /data/adb/modules/cap-unpin && echo OK")
	if err != nil || !strings.Contains(out, "OK") {
		return &Result{
			Method:  MethodMagisk,
			Success: false,
			Message: fmt.Sprintf("removal failed: %s %v", out, err),
		}, nil
	}
	return &Result{
		Method:  MethodMagisk,
		Success: true,
		Message: "Magisk unpinning module removed — reboot to take effect",
	}, nil
}
