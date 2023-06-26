import argparse
import datetime
import ipaddress
import math
import os

import matplotlib.pyplot as plt
import pandas as pd
import pygeoip
from . import report
from .alert import BotnetAlert, ExfiltrationAlert
from scipy.stats import norm

alerts = {}


def printq(*args):
    if not arguments.quiet:
        print(*args)


def dataExfiltration(percentage):
    percentage = int(percentage)
    p = percentage
    
    assert percentage <= 100 and percentage >= 0, "Percentage is invalid"
    
    printq(
        f"[!] IPs above the {percentage} percentile of downloads over uploads in this session.\n"
    )

    percentage = 1 - (percentage / 100)

    # Calculate the total downloaded and uploaded bytes per IP
    ratios = data.groupby(["src_ip"], as_index=False)[["down_bytes", "up_bytes"]].sum()

    # Calculate the ratio between downloaded and uploaded bytes
    ratios["ratio"] = ratios["down_bytes"] / ratios["up_bytes"]

    # Sort by ratio
    ratios = ratios.sort_values(["ratio"], ascending=False)

    # Top outliers base on percentage
    outliers = ratios.head(int(len(ratios) * percentage))

    printq(outliers)

    for (
        _,
        row,
    ) in outliers.iterrows():
        alerts.setdefault("exfiltrations", []).append(
            ExfiltrationAlert(
                gi=gi,
                gi2=gi2,
                down_byte=row.down_bytes,
                up_byte=row.up_bytes,
                percentage=p,
                addr=row.src_ip,
            )
        )


def botnet(subnet):
    printq(
        f"[!] Flows between internal host to common destinations in the same subnet ({subnet}), may indicate the existence of a internal botnet.\n"
    )

    subnet = ipaddress.IPv4Network(subnet)

    # Filter to src_ip for desired subnet
    same_subnet = data
    same_subnet["src_ip"] = same_subnet["src_ip"].astype(str)

    # Filter to src_ip and dst_ip in the same desired subnet
    same_subnet = same_subnet.loc[
        (data["src_ip"].apply(lambda x: ipaddress.IPv4Address(x) in subnet))
        & (data["dst_ip"].apply(lambda x: ipaddress.IPv4Address(x) in subnet))
    ]

    # Associates each dst_ip with a set of IPs and a set of timestamps
    same_subnet = same_subnet.groupby(["dst_ip"], as_index=False).agg(
        {"src_ip": list, "timestamp": list}
    )

    # Calculate the frequency of the communications
    def frequency(comms, period):
        return len(comms) / (period[-1] - period[0])

    same_subnet["frequency"] = same_subnet.apply(
        lambda x: frequency(x.src_ip, x.timestamp), axis=1
    )

    # Clean non relevant series
    same_subnet = same_subnet.drop(["timestamp"], axis=1)

    # Clean repeated IPs
    same_subnet["src_ip"] = same_subnet["src_ip"].apply(lambda x: list(set(x)))

    # Order
    same_subnet = same_subnet.sort_values(["frequency"], ascending=False)

    printq(same_subnet)

    for (
        _,
        row,
    ) in same_subnet.iterrows():
        alerts.setdefault("botnet", []).append(
            BotnetAlert(
                gi=gi,
                gi2=gi2,
                subnet=str(subnet),
                peers=row.src_ip,
                frequency=row.frequency,
                addr=row.dst_ip,
            )
        )


def countryVolume():
    printq(
        f"[!] Calculate the country of origin of the destination IPs and the connection volume for each country. Generating a PNG with the bar graph.\n"
    )

    # Analyses of destination countries connection volume
    countries = data
    countries["country"] = countries["dst_ip"].apply(
        lambda ip: gi.country_code_by_addr(ip)
    )

    # Associates each country with it's number of connection 
    # and the total data downloads by it. For normal flows
    # they should be directly proportional
    volume = countries.groupby(["country"]).agg(
        {"dst_ip": ["count"], "down_bytes": ["sum"]}
    )
    
    # Sorting the DataFrame by dst_ip column in descending order
    volume = volume.sort_values(("dst_ip", "count"), ascending=False)

    printq(volume)
    
    # Generates bar chart image
    countries = [x if x != "" else "Unknown" for x in volume.index]
    connections = [x[0] for x in volume['dst_ip'].values]

    fig, ax = plt.subplots(figsize=(15, 10))
    bar_width = 0.4  # Adjust this value to change the width of each bar

    # Plotting the bars for connections
    ax.barh(countries, connections, bar_width, align="edge", label='Connections')
    ax.set_xlabel("Number of Connections")
    ax.set_ylabel("Country")
    
    # Adding labels to the bars
    for i, conn in enumerate(connections):
        ax.text(conn, i, str(conn), va="center")
    ax.set_title("Number of Connections per Country")

    filepath = "connectionsxcountry"  # Specify the desired image filename
    fig.savefig(filepath)
    
    return f"""
# Connection volume by country

The correlation between connection volume and country of destination can be viewed in the graphic bellow.

![Volumebycountry]({filepath}.png)

<div style="page-break-after: always;"></div>
"""


def trafficDistribution():
    printq(
        f"[!] Distribution of connection volume during the day.\n"
    )
    
    traffic = data
    traffic["hour"] = pd.to_datetime(traffic["timestamp"] / 100.0, unit="s").dt.hour
    hourly = traffic["hour"].value_counts().sort_index()
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(hourly.index, hourly.values)
    ax.set_xlabel("Hours")
    ax.set_ylabel("Number of connections")
    ax.set_title("Connections per hour during a day")
    ax.set_xticks(range(24))

    filepath = "connectionsxhour"
    fig.savefig(fname=filepath)

    printq(hourly)

    return f"""
# Connection volume per hour

This graph ilustrates the number of connection per hour during a day

![Connectionsperhout]({filepath}.png)

<div style="page-break-after: always;"></div>

"""


def main():
    global data
    data = pd.read_parquet(arguments.data)

    global gi, gi2
    gi = pygeoip.GeoIP(arguments.gi)
    gi2 = pygeoip.GeoIP(arguments.gin)

    intro = f"""# Sentinel traffic report

This report was automatically generated at **{str(datetime.datetime.utcnow())}** by the **Sentinel** service.
"""

    # Clean operations
    operations = dict(arguments._get_kwargs())
    del operations["data"]
    del operations["gi"]
    del operations["gin"]
    del operations["quiet"]
    del operations["outfileMd"]

    for key, value in list(operations.items()):
        if value:
            value = f'"{value}"' if value and value != True else ""
            func = f"{key}({value})"
            printq()
            r = eval(func)
            if r:
                intro += r

    # Print results to pdf
    if dict(arguments._get_kwargs())["outfileMd"]:
        report.printReport(alerts, intro)


def cli():
    parser = argparse.ArgumentParser(description="Traffic analysis tool.")
    
    parser.add_argument(
        "--data", type=str, help="Path to datafile to analyze", required=True
    )

    parser.add_argument("-gi", type=str, help="Geolocation IP database", required=True)

    parser.add_argument(
        "-gin", type=str, help="Geolocation IP database with nameserver", required=True
    )

    parser.add_argument(
        "-dx",
        "--dataExfiltration",
        type=int,
        help="Threshold percentage for outliers in upload/download byte amount. Example '-dx 90' will return the top 10%%",
    )

    parser.add_argument(
        "-bn",
        "--botnet",
        type=str,
        help="Detecting possible botnet communication in specified networks, or all networks. Example '-bn 192.168.1.0/24' will search P2P communication within that network",
    )

    parser.add_argument(
        "-cv",
        "--countryVolume",
        action="store_true",
        help="Measures the connection volume per country",
    )

    parser.add_argument(
        "-td",
        "--trafficDistribution",
        action="store_true",
        help="Generates a graph illustrating the hourly distribution of the volume of connections during a day",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress stdout"
    )

    parser.add_argument(
        "-o",
        "--outfileMd",
        action="store_true",
        help="Export to markdown file"
    )

    global arguments
    arguments = parser.parse_args()

    main()
