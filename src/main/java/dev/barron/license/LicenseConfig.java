package dev.barron.license;

/**
 * Configuration for license server connection
 */
public class LicenseConfig {

    private boolean serverSideEnabled = false;
    private String serverUrl = "http://localhost:7742";
    private String licenseKey = "";

    public LicenseConfig() {
    }

    public boolean isServerSideEnabled() {
        return serverSideEnabled;
    }

    public void setServerSideEnabled(boolean serverSideEnabled) {
        this.serverSideEnabled = serverSideEnabled;
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(String serverUrl) {
        this.serverUrl = serverUrl;
    }

    public String getLicenseKey() {
        return licenseKey;
    }

    public void setLicenseKey(String licenseKey) {
        this.licenseKey = licenseKey;
    }

    /**
     * Validate configuration
     */
    public boolean isValid() {
        if (!serverSideEnabled) {
            return true; // Always valid when disabled
        }
        return serverUrl != null && !serverUrl.isEmpty()
                && licenseKey != null && !licenseKey.isEmpty();
    }
}
