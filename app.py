#!/usr/bin/env python3
import requests
import urllib3
import time
from prometheus_client import Gauge, start_http_server

# Disable insecure request warnings (for testing purposes only)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# HPE OneView API credentials and constants
ONEVIEW_HOST = ''
USERNAME = ''
PASSWORD = ''
API_VERSION = '4200'  # Updated API version

# Create a persistent session object
session = requests.Session()

# ----------------------------
# Prometheus metric definitions
# ----------------------------

# Gauge for overall resource counts.
oneview_count_metric = Gauge(
    'oneview_count',
    'Count of various OneView resources',
    ['category']
)

# Gauge for status counts.
oneview_status_metric = Gauge(
    'oneview_status',
    'Status count of various OneView resources',
    ['category', 'status']
)

# Gauge for server hardware information.
oneview_server_hardware_info = Gauge(
    'oneview_server_hardware_info',
    'Server Hardware information from OneView',
    ['name', 'serverName', 'shortModel', 'status']
)

# Gauge for server profiles information.
oneview_server_profiles_info = Gauge(
    'oneview_server_profiles_info',
    'Server Profile information from OneView',
    ['name', 'description', 'serialNumber', 'status']
)

# Gauge for alerts information.
oneview_alerts_info = Gauge(
    'oneview_alerts_info',
    'Alert information from OneView',
    ['description', 'urgency', 'severity', 'alertState', 'resourceName']
)

# Gauge for enclosures information.
oneview_enclosures_info = Gauge(
    'oneview_enclosures_info',
    'Enclosures information from OneView',
    ['name', 'serialNumber', 'enclosureModel', 'status']
)

# Gauge for ambient temperature in Celsius.
oneview_ambientTemperature_celcius_metric = Gauge(
    'oneview_ambientTemperature_celcius',
    'Ambient temperature as reported by the resource.',
    ['category', 'name', 'uuid']
)

# Gauge for average power consumption.
oneview_averagePower_watts_metric = Gauge(
    'oneview_averagePower_watts',
    'Average Power consumption as reported by the resource.',
    ['category', 'name', 'uuid']
)

# Gauge for peak power consumption.
oneview_peakPower_watts_metric = Gauge(
    'oneview_peakPower_watts',
    'Peak Power consumption as reported by the resource.',
    ['category', 'name', 'uuid']
)

# New Gauge for interconnects information.
oneview_interconnects_info = Gauge(
    'oneview_interconnects_info',
    'Interconnect information from OneView',
    ['type', 'model', 'portName', 'interconnectName', 'bayNumber', 'portHealthStatus']
)

# Gauge for interconnect port statistics.
oneview_interconnect_statistics_in_speed = Gauge(
    'oneview_interconnect_statistics_in_speed',
    'Interconnect port in speed (octets) as reported by the resource.',
    ['interconnectUid', 'portName']
)

oneview_interconnect_statistics_out_speed = Gauge(
    'oneview_interconnect_statistics_out_speed',
    'Interconnect port out speed (octets) as reported by the resource.',
    ['interconnectUid', 'portName']
)

# ----------------------------
# Helper functions and API calls
# ----------------------------

def authenticate():
    """
    Authenticate with the OneView API to get a session token.
    Update the session headers with the authentication token and API version.
    """
    login_data = {"userName": USERNAME, "password": PASSWORD}
    url = f"https://{ONEVIEW_HOST}/rest/login-sessions"
    response = session.post(url, json=login_data, verify=False, timeout=10)
    response.raise_for_status()
    token = response.json().get("sessionID")
    if not token:
        raise Exception("Login failed: No sessionID in response.")
    session.headers.update({"auth": token, "X-API-Version": API_VERSION})
    return token

def fetch_data(endpoint):
    """
    Fetch data from the specified endpoint.

    :param endpoint: The endpoint path (e.g., "server-hardware", "enclosures", etc.).
    :return: Parsed JSON data from the API.
    """
    url = f"https://{ONEVIEW_HOST}/rest/{endpoint}"
    response = session.get(url, verify=False)
    response.raise_for_status()
    return response.json()

# ----------------------------
# Metric Update Functions
# ----------------------------

def oneview_count():
    """
    Fetch counts for various OneView endpoints and update the Prometheus gauge.
    """
    endpoints = {
        "server-hardware": "server-hardware",
        "enclosures": "enclosures",
        "interconnects": "interconnects",
        "sas-interconnects": "sas-interconnects"
    }

    for category, endpoint in endpoints.items():
        try:
            data = fetch_data(endpoint)
            count = data.get("total", 0)
            oneview_count_metric.labels(category=category).set(count)
        except Exception:
            oneview_count_metric.labels(category=category).set(0)

def oneview_status():
    """
    Fetch status counts for selected OneView endpoints and update the Prometheus gauge.
    """
    endpoints = {
        "server-hardware": "server-hardware",
        "enclosures": "enclosures",
        "sas-interconnects": "sas-interconnects"
    }
    statuses = ["Critical", "Disabled", "OK", "Unknown", "Warning"]

    # Initialize statuses for each endpoint.
    for category in endpoints.keys():
        for status in statuses:
            oneview_status_metric.labels(category=category, status=status).set(0)

    for category, endpoint in endpoints.items():
        try:
            data = fetch_data(endpoint)
            members = data.get("members", [])
            status_counts = {s: 0 for s in statuses}
            for member in members:
                st = member.get("status")
                if st in status_counts:
                    status_counts[st] += 1
            for status in statuses:
                oneview_status_metric.labels(category=category, status=status).set(status_counts[status])
        except Exception:
            continue

def oneview_server_hardware_info_func():
    """
    Fetch server hardware details and update the corresponding Prometheus metric.
    """
    oneview_server_hardware_info.clear()
    try:
        data = fetch_data("server-hardware")
        for member in data.get("members", []):
            name = member.get("name", "unknown")
            server_name = member.get("serverName", "unknown")
            status = member.get("status", "unknown")
            short_model = member.get("model", "unknown")
            oneview_server_hardware_info.labels(
                name=name,
                serverName=server_name,
                shortModel=short_model,
                status=status
            ).set(1)
    except Exception:
        pass

def oneview_server_profiles_info_func():
    """
    Fetch server profiles details and update the corresponding Prometheus metric.
    """
    oneview_server_profiles_info.clear()
    try:
        data = fetch_data("server-profiles")
        for member in data.get("members", []):
            name = member.get("name", "unknown")
            description = member.get("description", "unknown")
            serial_number = member.get("serialNumber", "unknown")
            status = member.get("status", "unknown")
            oneview_server_profiles_info.labels(
                name=name,
                description=description,
                serialNumber=serial_number,
                status=status
            ).set(1)
    except Exception:
        pass

def oneview_alerts_info_func():
    """
    Fetch alert details and update the corresponding Prometheus metric.
    """
    oneview_alerts_info.clear()
    try:
        data = fetch_data("alerts")
        for member in data.get("members", []):
            description = member.get("description", "unknown")
            urgency = member.get("urgency", "unknown")
            severity = member.get("severity", "unknown")
            alert_state = member.get("alertState", "unknown")
            associated_resource = member.get("associatedResource", {})
            resource_name = associated_resource.get("resourceName", "unknown")
            oneview_alerts_info.labels(
                description=description,
                urgency=urgency,
                severity=severity,
                alertState=alert_state,
                resourceName=resource_name
            ).set(1)
    except Exception:
        pass

def oneview_enclosures_info_func():
    """
    Fetch enclosure details and update the corresponding Prometheus metric.
    """
    oneview_enclosures_info.clear()
    try:
        data = fetch_data("enclosures")
        for member in data.get("members", []):
            name = member.get("name", "unknown")
            serial_number = member.get("serialNumber", "unknown")
            enclosure_model = member.get("enclosureModel", member.get("model", "unknown"))
            status = member.get("status", "unknown")
            oneview_enclosures_info.labels(
                name=name,
                serialNumber=serial_number,
                enclosureModel=enclosure_model,
                status=status
            ).set(1)
    except Exception:
        pass

def oneview_ambientTemperature_celcius():
    """
    For each resource in 'enclosures' and 'server-hardware', extract its UUID from the 'uri'
    and query its utilization endpoint for AmbientTemperature using:
       /rest/<category>/{UUID}/utilization?fields=AmbientTemperature
    For interconnects, query:
       /rest/interconnects/{UUID}/utilization
    and then select the metric with metricName "Temperature" to extract the latest sample
    from samples[0][0][1].

    Update the Prometheus gauge (oneview_ambientTemperature_celcius_metric) with the value.
    """
    oneview_ambientTemperature_celcius_metric.clear()

    # Process enclosures and server-hardware using the query-string endpoint.
    for category in ["enclosures", "server-hardware"]:
        try:
            data = fetch_data(category)
        except Exception:
            continue

        for member in data.get("members", []):
            resource_name = member.get("name", "unknown")
            uri = member.get("uri", "")
            uuid = uri.split("/")[-1] if uri else "unknown"
            endpoint = f"{category}/{uuid}/utilization?fields=AmbientTemperature"

            try:
                util_data = fetch_data(endpoint)
                metric_list = util_data.get("metricList", [])
                if metric_list and len(metric_list) > 0:
                    samples = metric_list[0].get("metricSamples", [])
                    if samples and len(samples) > 0:
                        ambient_temp = samples[0][1]
                    else:
                        ambient_temp = 0
                else:
                    ambient_temp = 0
            except Exception:
                ambient_temp = 0

            oneview_ambientTemperature_celcius_metric.labels(
                category=category,
                name=resource_name,
                uuid=uuid
            ).set(ambient_temp)

    # Process interconnects using different logic.
    try:
        inter_data = fetch_data("interconnects")
    except Exception:
        inter_data = {}

    for member in inter_data.get("members", []):
        resource_name = member.get("name", "unknown")
        uri = member.get("uri", "")
        uuid = uri.split("/")[-1] if uri else "unknown"
        endpoint = f"interconnects/{uuid}/utilization"
        ambient_temp = 0
        try:
            util_data = fetch_data(endpoint)
            metric_list = util_data.get("metricList", [])
            # Find the metric with metricName "Temperature"
            for metric in metric_list:
                if metric.get("metricName") == "Temperature":
                    samples = metric.get("metricSamples", [])
                    if samples and len(samples) > 0 and len(samples[0]) > 0:
                        ambient_temp = samples[0][0][1]
                    break
        except Exception:
            ambient_temp = 0

        oneview_ambientTemperature_celcius_metric.labels(
            category="interconnects",
            name=resource_name,
            uuid=uuid
        ).set(ambient_temp)

def oneview_power_info():
    """
    For each resource in 'enclosures' and 'server-hardware', extract its UUID from the 'uri'
    and query its utilization endpoints for AveragePower and PeakPower using the query parameter.

    For interconnects, query /rest/interconnects/{UUID}/utilization and iterate over the returned
    metricList to extract the values for PowerAverageWatts and PowerPeakWatts.

    Update the Prometheus gauges (oneview_averagePower_watts_metric and oneview_peakPower_watts_metric)
    with the latest values.
    """
    # Clear previous power metric values.
    oneview_averagePower_watts_metric.clear()
    oneview_peakPower_watts_metric.clear()

    # Process enclosures and server-hardware.
    for category in ["enclosures", "server-hardware"]:
        try:
            data = fetch_data(category)
        except Exception:
            continue

        for member in data.get("members", []):
            resource_name = member.get("name", "unknown")
            uri = member.get("uri", "")
            uuid = uri.split("/")[-1] if uri else "unknown"
            # Build endpoints with query parameters.
            avg_endpoint = f"{category}/{uuid}/utilization?fields=AveragePower"
            peak_endpoint = f"{category}/{uuid}/utilization?fields=PeakPower"

            # Fetch AveragePower.
            try:
                avg_data = fetch_data(avg_endpoint)
                metric_list = avg_data.get("metricList", [])
                if metric_list and len(metric_list) > 0:
                    samples = metric_list[0].get("metricSamples", [])
                    if samples and len(samples) > 0:
                        average_power = samples[0][1]
                    else:
                        average_power = 0
                else:
                    average_power = 0
            except Exception:
                average_power = 0

            # Fetch PeakPower.
            try:
                peak_data = fetch_data(peak_endpoint)
                metric_list = peak_data.get("metricList", [])
                if metric_list and len(metric_list) > 0:
                    samples = metric_list[0].get("metricSamples", [])
                    if samples and len(samples) > 0:
                        peak_power = samples[0][1]
                    else:
                        peak_power = 0
                else:
                    peak_power = 0
            except Exception:
                peak_power = 0

            oneview_averagePower_watts_metric.labels(
                category=category,
                name=resource_name,
                uuid=uuid
            ).set(average_power)

            oneview_peakPower_watts_metric.labels(
                category=category,
                name=resource_name,
                uuid=uuid
            ).set(peak_power)

    # Process interconnects with different logic.
    try:
        inter_data = fetch_data("interconnects")
    except Exception:
        inter_data = {}

    for member in inter_data.get("members", []):
        resource_name = member.get("name", "unknown")
        uri = member.get("uri", "")
        uuid = uri.split("/")[-1] if uri else "unknown"
        utilization_endpoint = f"interconnects/{uuid}/utilization"
        average_power = 0
        peak_power = 0
        try:
            util_data = fetch_data(utilization_endpoint)
            metric_list = util_data.get("metricList", [])
            for metric in metric_list:
                if metric.get("metricName") == "PowerAverageWatts":
                    samples = metric.get("metricSamples", [])
                    if samples and len(samples) > 0 and len(samples[0]) > 0:
                        average_power = samples[0][0][1]
                elif metric.get("metricName") == "PowerPeakWatts":
                    samples = metric.get("metricSamples", [])
                    if samples and len(samples) > 0 and len(samples[0]) > 0:
                        peak_power = samples[0][0][1]
        except Exception:
            average_power = 0
            peak_power = 0

        oneview_averagePower_watts_metric.labels(
            category="interconnects",
            name=resource_name,
            uuid=uuid
        ).set(average_power)

        oneview_peakPower_watts_metric.labels(
            category="interconnects",
            name=resource_name,
            uuid=uuid
        ).set(peak_power)

def oneview_interconnect_statistics_info():
    """
    Fetch the list of interconnects, then for each interconnect hit its statistics endpoint,
    and iterate over its portStatistics array. For each port, extract:
      - portName (from the portStatistics object)
      - inSpeed: using commonStatistics.rfc1213IfInOctets (default to 0 if missing)
      - outSpeed: using commonStatistics.rfc1213IfOutOctets (default to 0 if missing)
    The interconnect uid is extracted from the interconnect's "uri" field.
    For each port, update the Prometheus gauges:
      - oneview_interconnect_statistics_in_speed with the numeric inSpeed value.
      - oneview_interconnect_statistics_out_speed with the numeric outSpeed value.
    """
    oneview_interconnect_statistics_in_speed.clear()
    oneview_interconnect_statistics_out_speed.clear()
    
    try:
        inter_data = fetch_data("interconnects")
    except Exception:
        return
    
    for inter in inter_data.get("members", []):
        uid = inter.get("uri", "").split("/")[-1] if inter.get("uri") else "unknown"
        # Fetch statistics for this interconnect.
        try:
            stats = fetch_data(f"interconnects/{uid}/statistics")
        except Exception:
            continue
        
        for port in stats.get("portStatistics", []):
            port_name = port.get("portName", "unknown")
            common_stats = port.get("commonStatistics", {})
            # Use only rfc1213IfInOctets and rfc1213IfOutOctets.
            in_octets = common_stats.get("rfc1213IfInOctets", 0)
            out_octets = common_stats.get("rfc1213IfOutOctets", 0)
            
            oneview_interconnect_statistics_in_speed.labels(
                interconnectUid=uid,
                portName=port_name
            ).set(in_octets)
            
            oneview_interconnect_statistics_out_speed.labels(
                interconnectUid=uid,
                portName=port_name
            ).set(out_octets)

# ----------------------------
# Main execution loop
# ----------------------------

def main():
    # Start the Prometheus HTTP server on port 8000.
    start_http_server(8000)

    # Authenticate with OneView.
    authenticate()

    # Periodically update all metrics.
    while True:
        oneview_count()
        oneview_status()
        oneview_server_hardware_info_func()
        oneview_server_profiles_info_func()
        oneview_alerts_info_func()
        oneview_enclosures_info_func()
        oneview_ambientTemperature_celcius()
        oneview_power_info()
        oneview_interconnect_statistics_info()
        time.sleep(60)

if __name__ == "__main__":
    main()
